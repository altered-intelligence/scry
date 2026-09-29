"""Ingestion orchestrator.

Pulls feeds, fetches articles, deduplicates, persists to Article rows. The
extraction/enrichment passes are invoked after ingestion and stored alongside.

This module is intentionally orchestration-only — no parsing or extraction
logic lives here.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.ingestion.cve_feed import parse_kev_json
from scry.ingestion.fetcher import FetchResult, SafeFetcher
from scry.ingestion.policy import CollectionPolicyEngine, PolicyDecision
from scry.ingestion.rss import is_feed_content_type, parse_feed_text
from scry.ingestion.source_registry import SourceRegistry
from scry.logging import get_logger
from scry.models import CVE, Article, Source, SourceFetch
from scry.parsing.article_parser import parse_article

logger = get_logger("ingest_engine")
PARSER_VERSION = "0.1"


class IngestionEngine:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.policy = CollectionPolicyEngine()
        self.registry = SourceRegistry(session)

    async def ingest_url(self, url: str, *, source_id: int | None = None) -> Article | None:
        source = self.session.get(Source, source_id) if source_id else None
        policy_name = source.collection_policy if source else "safe_public_web"
        enabled = bool(source.enabled) if source else True
        safety_mode = source.safety_mode if source else None
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
                rate_limit_per_minute=source.rate_limit_per_minute if source else 10,
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
            if is_feed_content_type(content_type) or feed_res.text.lstrip().startswith("<?xml"):
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
            for entry in entries[:200]:
                if self._is_duplicate_url(entry.url):
                    continue
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
                persisted += 1
            self.session.commit()
            return {"articles": persisted, "feed_entries": len(entries)}

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

    async def fetch_full_content(self, limit: int = 50) -> dict[str, int]:
        """Second-pass: fetch the full HTML for articles that only have RSS summaries.

        Identifies articles whose extracted_text is short (< 1000 chars) and where
        no full HTML is stored, then fetches and parses the full article URL.
        Returns counts of updated and failed articles.
        """
        updated = 0
        failed = 0
        skipped = 0

        # Articles with short content that haven't had full fetch yet
        stubs = self.session.scalars(
            select(Article)
            .where(Article.url.isnot(None))
            .where(Article.raw_html.is_(None))
            .order_by(Article.id.desc())
            .limit(limit * 3)  # over-fetch to account for skips
        ).all()

        candidates = [a for a in stubs if len(a.extracted_text or "") < 1000][:limit]
        logger.info("full_fetch_candidates", count=len(candidates))

        for article in candidates:
            try:
                source = self.session.get(Source, article.source_id) if article.source_id else None
                policy_name = source.collection_policy if source else "safe_public_web"
                safety_mode = source.safety_mode if source else None
                source_enabled = source.enabled if source else True
                decision = self.policy.evaluate(
                    policy_name=policy_name,
                    source_enabled=source_enabled,
                    source_safety_mode=safety_mode,
                )
                if not decision.allowed:
                    skipped += 1
                    continue

                rate = source.rate_limit_per_minute if source else 10

                async with SafeFetcher() as fetcher:
                    res = await fetcher.fetch(article.url, policy=decision, rate_limit_per_minute=rate)

                if res.error or not res.text or len(res.text) < 500:
                    failed += 1
                    continue

                parsed = parse_article(res.text, url=article.url)
                full_text = parsed.text or res.text
                if len(full_text) > len(article.extracted_text or ""):
                    article.extracted_text = full_text[:100_000]
                    article.raw_html = res.text[:500_000]
                    if parsed.title and not article.title:
                        article.title = parsed.title
                    # Reset extractor version so pipeline re-runs IOC extraction
                    article.extractor_version = "0"
                    updated += 1
            except Exception as exc:
                logger.warning("full_fetch_error", article_id=article.id, exc=str(exc))
                failed += 1

        self.session.commit()
        logger.info("full_fetch_done", updated=updated, failed=failed, skipped=skipped)
        return {"updated": updated, "failed": failed, "skipped": skipped}

    # ----- helpers -----

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

        article = Article(
            source_id=source.id if source else None,
            title="",
            url=fetch.url,
            ingested_at=datetime.now(UTC),
            extracted_text="",
            raw_html=fetch.text if policy.fetch_mode != "metadata_only" else None,
            content_hash=fetch.content_hash,
            source_confidence=source.baseline_confidence if source else 60,
            parser_version=PARSER_VERSION,
        )
        self.session.add(article)
        self.session.commit()
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
