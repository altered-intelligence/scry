"""Ingestion orchestrator.

Pulls feeds, fetches articles, deduplicates, persists to Article rows. The
extraction/enrichment passes are invoked after ingestion and stored alongside.

This module is intentionally orchestration-only — no parsing or extraction
logic lives here.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from scry.ingestion.collection_window import entry_in_window, get_window_days
from scry.ingestion.cve_feed import parse_kev_json
from scry.ingestion.fetcher import FetchResult, SafeFetcher
from scry.ingestion.policy import CollectionPolicyEngine, PolicyDecision
from scry.ingestion.rss import looks_like_feed, parse_feed_text
from scry.ingestion.source_registry import SourceRegistry
from scry.logging import get_logger
from scry.models import CVE, Article, Source, SourceFetch
from scry.parsing.article_parser import parse_article
from scry.search import embeddings, fts

logger = get_logger("ingest_engine")
PARSER_VERSION = "0.1"
# Same caps the second-pass full-content fetch applies.
MAX_TEXT_CHARS = 100_000
MAX_RAW_HTML_CHARS = 500_000
# Articles with less text than this are RSS stubs worth a full-page fetch.
SHORT_TEXT_CHARS = 1000


class IngestionEngine:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.policy = CollectionPolicyEngine()
        self.registry = SourceRegistry(session)

    async def ingest_url(self, url: str, *, source_id: int | None = None) -> Article | None:
        source = self.session.get(Source, source_id) if source_id else self._default_manual_source()
        policy_name = source.collection_policy
        enabled = bool(source.enabled)
        safety_mode = source.safety_mode
        decision = self.policy.evaluate(
            policy_name=policy_name,
            source_enabled=enabled,
            source_safety_mode=safety_mode,
        )
        if not decision.allowed:
            logger.warning("ingest_blocked", url=url, reason=decision.reason)
            return None
        async with SafeFetcher() as fetcher:
            result = await fetcher.fetch(
                url,
                policy=decision,
                rate_limit_per_minute=source.rate_limit_per_minute,
            )
        return self._persist_fetch(source, result, decision, single_article=True)

    async def ingest_source(self, source: Source) -> dict[str, int]:
        decision = self.policy.evaluate(
            policy_name=source.collection_policy,
            source_enabled=source.enabled,
            source_safety_mode=source.safety_mode,
        )
        if not decision.allowed:
            logger.warning("source_blocked", source=source.name, reason=decision.reason)
            return {"articles": 0, "blocked": 1}

        async with SafeFetcher() as fetcher:
            feed_url = source.feed or source.url
            feed_res = await fetcher.fetch(
                feed_url, policy=decision, rate_limit_per_minute=source.rate_limit_per_minute
            )
            if feed_res.status_code is None or feed_res.error:
                self._record_fetch(source, feed_res)
                return {"articles": 0, "errors": 1}
            self._record_fetch(source, feed_res)

            content_type = feed_res.headers.get("content-type", "")
            if looks_like_feed(content_type, feed_res.text):
                entries = parse_feed_text(feed_res.text)
            elif "application/json" in content_type and "kev" in (source.name or "").lower():
                # CISA KEV style JSON — turn into CVE rows directly
                count = self._persist_kev(feed_res.text)
                return {"articles": 0, "cves": count}
            else:
                # Treat as a single article (e.g. a single blog post URL was given)
                article = self._persist_fetch(source, feed_res, decision, single_article=True)
                return {"articles": 1 if article else 0}

            persisted = 0
            window_skipped = 0
            window_days = get_window_days(self.session)
            seen_urls: set[str] = set()  # in-feed dupes: the DB check can't see pending rows (autoflush off)
            new_articles: list[Article] = []
            for entry in entries[:200]:
                if not entry_in_window(entry.published_at, window_days, datetime.now(UTC)):
                    window_skipped += 1
                    continue
                if entry.url in seen_urls or self._is_duplicate_url(entry.url):
                    continue
                seen_urls.add(entry.url)
                article = Article(
                    source_id=source.id,
                    title=entry.title or "(no title)",
                    url=entry.url,
                    author=entry.author,
                    published_at=entry.published_at,
                    ingested_at=datetime.now(UTC),
                    extracted_text=(entry.summary or "")[:50_000],
                    summary=entry.summary,
                    raw_html=entry.content_html,
                    content_hash=hashlib.sha256(
                        ((entry.content_html or entry.summary or entry.title) or "").encode("utf-8")
                    ).hexdigest(),
                    source_confidence=source.baseline_confidence,
                    parser_version=PARSER_VERSION,
                    tags=list(source.tags or []),
                )
                self.session.add(article)
                new_articles.append(article)
                persisted += 1
            self.session.commit()
            self._index_fts([a.id for a in new_articles])
            if window_skipped:
                logger.info("window_filtered", source=source.name, skipped=window_skipped, days=window_days)
            return {"articles": persisted, "feed_entries": len(entries), "window_skipped": window_skipped}

    async def ingest_all(self) -> dict[str, int]:
        totals: dict[str, int] = {"articles": 0, "cves": 0, "errors": 0, "blocked": 0}
        for source in self.registry.enabled_sources():
            try:
                res = await self.ingest_source(source)
            except Exception as exc:
                logger.exception("source_ingest_failed", source=source.name, exc=str(exc))
                totals["errors"] += 1
                continue
            for k, v in res.items():
                totals[k] = totals.get(k, 0) + v
        return totals

    async def fetch_full_content(
        self,
        limit: int = 50,
        *,
        max_age_hours: int | None = None,
        retry_after_hours: int = 0,
    ) -> dict[str, int]:
        """Second-pass: fetch the full page for articles that only have RSS summaries.

        Candidates are articles with no stored HTML whose text is short
        (< ``SHORT_TEXT_CHARS``) and whose source is enabled; newest first.

        - ``max_age_hours`` limits candidates to recently ingested articles
          (the scheduler uses it so articles whose HTML was pruned by
          retention are never refetched).
        - ``retry_after_hours`` skips URLs with a failed fetch recorded in
          ``source_fetches`` within that window (the scheduler's back-off).
        - A page that fetches fine but is no longer than the stored text is
          still marked done (its HTML is stored), so genuinely short pages
          are not refetched every cycle.

        Returns counts: updated (longer text stored), unchanged, failed, skipped.
        """
        now = datetime.now(UTC)
        stmt = (
            select(Article)
            .outerjoin(Source, Source.id == Article.source_id)
            .where(Article.url.isnot(None), Article.raw_html.is_(None))
            .where(func.length(Article.extracted_text) < SHORT_TEXT_CHARS)
            .where(or_(Source.id.is_(None), Source.enabled.is_(True)))
        )
        if max_age_hours:
            stmt = stmt.where(
                func.coalesce(Article.ingested_at, Article.created_at) >= now - timedelta(hours=max_age_hours)
            )
        if retry_after_hours:
            recent_failure = exists().where(
                SourceFetch.url == Article.url,
                SourceFetch.error.isnot(None),
                SourceFetch.fetched_at >= now - timedelta(hours=retry_after_hours),
            )
            stmt = stmt.where(~recent_failure)
        candidates = self.session.scalars(stmt.order_by(Article.id.desc()).limit(limit)).all()
        logger.info("full_fetch_candidates", count=len(candidates))

        updated = unchanged = failed = skipped = 0
        updated_ids: list[int] = []

        # One fetcher for the whole batch so its per-host rate limiter works.
        async with SafeFetcher() as fetcher:
            for article in candidates:
                source = self.session.get(Source, article.source_id) if article.source_id else None
                reason: str | None = None
                try:
                    decision = self.policy.evaluate(
                        policy_name=source.collection_policy if source else "safe_public_web",
                        source_enabled=source.enabled if source else True,
                        source_safety_mode=source.safety_mode if source else None,
                    )
                    if not decision.allowed:
                        skipped += 1
                        continue
                    res = await fetcher.fetch(
                        article.url,
                        policy=decision,
                        rate_limit_per_minute=source.rate_limit_per_minute if source else 10,
                    )
                    if res.error or not res.text or len(res.text) < 500:
                        reason = res.error or "response body too short"
                        status = res.status_code
                    else:
                        parsed = parse_article(res.text, url=article.url)
                        if len(parsed.text or "") > len(article.extracted_text or ""):
                            article.extracted_text = parsed.text[:MAX_TEXT_CHARS]
                            article.raw_html = res.text[:MAX_RAW_HTML_CHARS]
                            if parsed.title and not article.title:
                                article.title = parsed.title[:1024]
                            # Reset extractor version so the pipeline re-runs extraction.
                            article.extractor_version = "0"
                            updated += 1
                            updated_ids.append(article.id)
                        else:
                            # Fetched fine, nothing longer to store: keep the HTML so
                            # this article stops being a candidate.
                            article.raw_html = res.text[:MAX_RAW_HTML_CHARS]
                            unchanged += 1
                        self.session.commit()
                        continue
                except Exception as exc:
                    logger.warning("full_fetch_error", article_id=article.id, exc=str(exc))
                    self.session.rollback()
                    reason, status = f"{type(exc).__name__}: {exc}", None

                failed += 1
                if source is not None:  # back-off marker + "collection gaps" visibility
                    self._record_fetch(
                        source,
                        FetchResult(url=article.url, status_code=status, error=str(reason)[:500]),
                    )

        self._index_fts(updated_ids)
        logger.info("full_fetch_done", updated=updated, unchanged=unchanged, failed=failed, skipped=skipped)
        return {"updated": updated, "unchanged": unchanged, "failed": failed, "skipped": skipped}

    def _index_fts(self, article_ids: list[int]) -> None:
        """Refresh FTS5 entries + embeddings for newly ingested/updated articles.

        Best-effort: a search-index hiccup must never fail an ingest.
        """
        if not article_ids:
            return
        try:
            fts.index_rows(self.session, "article", article_ids)
            embeddings.sync_article_embeddings(self.session, article_ids)
            self.session.commit()
        except Exception as exc:  # pragma: no cover - defensive
            self.session.rollback()
            logger.warning("fts_index_failed", exc=str(exc))

    # ----- helpers -----

    def _default_manual_source(self) -> Source:
        """Get-or-create the catch-all source for ad-hoc URL ingests.

        ``POST /ingest/url`` without a source_id previously inserted an
        Article with ``source_id=None`` against a non-nullable column (500).
        Manual ingests get a low baseline confidence and the safest policy.
        """
        src = self.session.scalar(select(Source).where(Source.name == "Manual"))
        if src is None:
            src = Source(
                name="Manual",
                type="manual",
                url="",
                enabled=True,
                baseline_confidence=50,
                collection_policy="safe_public_web",
            )
            self.session.add(src)
            self.session.commit()
        return src

    def _persist_fetch(
        self, source: Source | None, fetch: FetchResult, policy: PolicyDecision, *, single_article: bool
    ) -> Article | None:
        if source is not None:
            self._record_fetch(source, fetch)
        if fetch.status_code is None or fetch.error or not single_article:
            return None
        if self._is_duplicate_url(fetch.url):
            existing = self.session.scalar(select(Article).where(Article.url == fetch.url))
            return existing

        # Parse the page NOW. Without this the article was stored with an empty
        # title and empty text, so extraction found nothing and nothing ever
        # re-parsed it (the second-pass full-content fetch only selects rows
        # with raw_html IS NULL, which ad-hoc ingests never are).
        metadata_only = policy.fetch_mode == "metadata_only"
        parsed = parse_article(fetch.text, url=fetch.url)
        article = Article(
            source_id=source.id if source else None,
            title=(parsed.title or "(no title)")[:1024],
            url=fetch.url,
            canonical_url=(parsed.canonical_url or None) and parsed.canonical_url[:2048],
            author=(parsed.author or None) and parsed.author[:255],
            language=(parsed.language or None) and parsed.language[:16],
            ingested_at=datetime.now(UTC),
            # metadata_only sources keep metadata, never page content.
            extracted_text="" if metadata_only else (parsed.text or "")[:MAX_TEXT_CHARS],
            raw_html=None if metadata_only else fetch.text[:MAX_RAW_HTML_CHARS],
            content_hash=fetch.content_hash,
            source_confidence=source.baseline_confidence if source else 60,
            parser_version=PARSER_VERSION,
        )
        self.session.add(article)
        self.session.commit()
        self._index_fts([article.id])
        return article

    def _is_duplicate_url(self, url: str) -> bool:
        return self.session.scalar(select(Article.id).where(Article.url == url)) is not None

    def _record_fetch(self, source: Source, fetch: FetchResult) -> None:
        self.session.add(
            SourceFetch(
                source_id=source.id,
                fetched_at=datetime.now(UTC),
                status_code=fetch.status_code,
                url=fetch.url,
                content_hash=fetch.content_hash,
                bytes_downloaded=len(fetch.content),
                duration_ms=fetch.elapsed_ms,
                error=fetch.error,
            )
        )
        self.session.commit()

    def _persist_kev(self, body: str) -> int:
        entries = parse_kev_json(body)
        count = 0
        for entry in entries:
            cve = self.session.scalar(select(CVE).where(CVE.cve_id == entry.cve_id))
            if cve is None:
                cve = CVE(cve_id=entry.cve_id)
                self.session.add(cve)
            cve.vendor = entry.vendor or cve.vendor
            cve.product = entry.product or cve.product
            cve.description = entry.short_description or cve.description
            cve.kev = True
            cve.exploited_in_the_wild = True
            cve.ransomware_associated = cve.ransomware_associated or entry.ransomware_associated
            cve.is_microsoft = (entry.vendor or "").lower().startswith("microsoft") or cve.is_microsoft
            count += 1
        self.session.commit()
        return count
