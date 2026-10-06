"""End-to-end pipeline.

Given an Article row, runs extraction → enrichment → scoring → persistence
of derived objects (observables, observable_mentions, entities,
entity_mentions, claims, relationships, attack mappings). Routing to the
analyst review queue happens here too.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from scry.alias_resolution import resolve_canonical, upsert_entity
from scry.enrichment import EnrichmentEngine
from scry.extraction import EXTRACTOR_VERSION, Extractor
from scry.extraction.classifiers import classify_all
from scry.extraction.ioc_extractor import local_context
from scry.extraction.relationship_extractor import evidence_window
from scry.logging import get_logger
from scry.models import (
    AnalystReview,
    Article,
    AttackMapping,
    Claim,
    Entity,
    EntityMention,
    Observable,
    ObservableMention,
    Relationship,
)
from scry.parsing.redactor import redact_secrets
from scry.review.routing import should_route_to_review
from scry.schemas.extraction import (
    ExtractionResult,
    IOCCandidate,
    RelationshipCandidate,
)
from scry.scoring import SCORING_MODEL_VERSION
from scry.scoring.confidence import ConfidenceInputs, ConfidenceScorer
from scry.scoring.lifecycle import LifecycleEngine
from scry.scoring.risk import RiskInputs, RiskScorer, expiration_from_ttl, recency_days
from scry.search import embeddings, fts

logger = get_logger("pipeline")

# Extractor tags that count as benign context in risk scoring.
BENIGN_CONTEXT_TAGS = frozenset({"possible-filename", "reference-context", "victim-context"})
# A vendor calls the indicator clean: VirusTotal with no malicious/suspicious
# votes and at least this many harmless ones, or GreyNoise "benign".
VT_CLEAN_MIN_HARMLESS = 20


def vendor_clean_flags(enrichment: dict) -> list[str]:
    flags: list[str] = []
    vt = enrichment.get("virustotal") or {}
    stats = vt.get("last_analysis_stats") or {}
    if (
        stats
        and not vt.get("not_found")
        and int(stats.get("malicious") or 0) == 0
        and int(stats.get("suspicious") or 0) == 0
        and int(stats.get("harmless") or 0) >= VT_CLEAN_MIN_HARMLESS
    ):
        flags.append("vendor-clean:virustotal")
    gn = enrichment.get("greynoise") or {}
    if str(gn.get("classification") or "").lower() == "benign":
        flags.append("vendor-clean:greynoise")
    return flags


# Observable mentions the pipeline did not create and must never delete.
PRESERVED_MENTION_METHODS = frozenset({"manual_import"})


def _as_utc(dt: datetime) -> datetime:
    """Treat naive datetimes (SQLite round-trip) as UTC for safe comparison."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class CTIPipeline:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.extractor = Extractor()
        self.extractor.ioc.reference_hosts |= self._source_hosts()
        self.enrichment = EnrichmentEngine(session)
        self.confidence = ConfidenceScorer()
        self.risk = RiskScorer()
        self.lifecycle = LifecycleEngine(session)

    def process_article(self, article: Article) -> ExtractionResult:
        # Idempotent reprocessing: drop rows previously derived from this
        # article's text so re-runs (fetch_full_content resets, OTX updates,
        # `scry extract`, version bumps) never multiply mentions/claims/etc.
        self._clear_derived_rows(article)

        # Redact secrets first — never index credentials.
        redaction = redact_secrets(article.extracted_text or "")
        if redaction.counts:
            logger.info("redacted_secrets", article_id=article.id, counts=redaction.counts)
            article.extracted_text = redaction.redacted_text

        result = self.extractor.process(
            article_text=article.extracted_text or "",
            article_title=article.title or "",
            article_id=article.id,
        )
        article.tags = sorted(set([*article.tags, *result.tags]))
        article.extractor_version = EXTRACTOR_VERSION

        # Source provenance applies to every IOC in the article; actor and
        # malware attribution only to IOCs whose own context names them, so a
        # roundup that mentions Cl0p once does not tag every CVE in it.
        context_tags = self._context_tags(article, result)
        entity_tags = self._entity_tag_patterns(result)

        # Persist observables and mentions.
        observable_ids: list[int] = []
        for ioc in result.iocs:
            local_text = ioc.context_window or ioc.evidence_text or ""
            # Victims are not attributed to the actor that hit them.
            local_entity_tags = (
                []
                if "victim-context" in ioc.tags
                else [tag for patt, tags in entity_tags if patt.search(local_text) for tag in tags]
            )
            ioc.tags = sorted(set([*ioc.tags, *context_tags, *local_entity_tags]))
            ob = self._upsert_observable(ioc, article)
            observable_ids.append(ob.id)
            self._enrich_and_score(ob, ioc, article)
            self._maybe_route_observable_to_review(ob, ioc, article)

        # Persist entities and mentions.
        entity_ids: list[int] = []
        for ent in result.entities:
            entity = upsert_entity(
                self.session,
                surface_form=ent.surface_form,
                entity_type=ent.type,
            )
            entity_ids.append(entity.id)
            self.session.add(
                EntityMention(
                    entity_id=entity.id,
                    article_id=article.id,
                    evidence_text=ent.evidence_text,
                    extraction_method=ent.extraction_method,
                    extraction_confidence=ent.extraction_confidence,
                )
            )

        # Persist claims.
        claim_ids: list[int] = []
        for claim in result.claims:
            row = Claim(
                claim_text=claim.claim_text,
                claim_type=claim.claim_type,
                confidence=claim.confidence,
                evidence_text=claim.evidence_text,
                article_id=article.id,
                explicit_or_inferred=claim.explicit_or_inferred,
                extraction_method=claim.extraction_method,
                extractor_version=EXTRACTOR_VERSION,
            )
            row.needs_review = should_route_to_review(claim, article)
            prior = self._closed_claim_review(article.id, claim.evidence_text) if row.needs_review else None
            if prior is not None:
                # An analyst already decided on this exact claim in a previous
                # run: keep the decision instead of reopening it.
                row.needs_review = False
                row.review_status = prior.disposition or "reviewed"
            elif row.needs_review:
                row.review_status = "pending"
            self.session.add(row)
            self.session.flush()
            claim_ids.append(row.id)
            if prior is not None:
                prior.item_id = row.id  # keep the audit trail pointing at the live claim
            elif row.needs_review:
                self._add_review_once(
                    item_type="claim",
                    item_id=row.id,
                    reason=f"claim type {claim.claim_type} needs review",
                    confidence=claim.confidence,
                    article_id=article.id,
                    evidence_text=claim.evidence_text,
                    recommended_action="human_review",
                )

        # Persist relationships once entity ids exist.
        self._persist_relationships(result.relationships, article)

        # ATT&CK mappings.
        for tid in result.attack_techniques:
            res = self.enrichment.attack.enrich(tid).fields
            self.session.add(
                AttackMapping(
                    parent_type="article",
                    parent_id=article.id,
                    technique_id=res.get("technique_id", tid),
                    technique_name=res.get("technique_name"),
                    tactic=res.get("tactic"),
                    confidence=60,
                    evidence_text=None,
                    explicit_or_inferred="inferred",
                )
            )

        self.session.commit()
        self._sync_fts(article.id, observable_ids, entity_ids, claim_ids)
        return result

    def _sync_fts(
        self, article_id: int, observable_ids: list[int], entity_ids: list[int], claim_ids: list[int]
    ) -> None:
        """Refresh search-side derived data (FTS5 + embeddings) this run touched.

        Runs after the main commit so index values read committed content;
        failures never break the pipeline (LIKE fallback keeps search alive).
        The article embedding matters here because redaction may have
        rewritten ``extracted_text`` during this run.
        """
        try:
            fts.index_rows(self.session, "article", [article_id])
            fts.index_rows(self.session, "observable", observable_ids)
            fts.index_rows(self.session, "entity", entity_ids)
            fts.index_rows(self.session, "claim", claim_ids)
            embeddings.sync_article_embeddings(self.session, [article_id])
            self.session.commit()
        except Exception as exc:  # pragma: no cover - defensive
            self.session.rollback()
            logger.warning("fts_sync_failed", article_id=article_id, exc=str(exc))

    # -------- helpers --------

    def _clear_derived_rows(self, article: Article) -> None:
        """Delete extraction products of a prior run for this article.

        Observables themselves are upserted (shared across articles) so they
        survive; only per-article rows are rebuilt. Open auto-routed claim
        reviews for this article would dangle once their claims are replaced,
        so they are dropped too — reviews an analyst already touched are kept
        as an audit trail.
        """
        # FTS5: old claim index entries must go BEFORE the content rows
        # (external-content FTS5 resolves deleted tokens through the content
        # table — once the row is gone the index entry is unrecoverable).
        fts.unindex_claims_for_article(self.session, article.id)
        # Mentions written by importers (hunt workbooks: aliases, addresses,
        # people...) are not reproducible by the extractor; keep them.
        self.session.execute(
            delete(ObservableMention).where(
                ObservableMention.article_id == article.id,
                ObservableMention.extraction_method.not_in(PRESERVED_MENTION_METHODS),
            )
        )
        self.session.execute(delete(EntityMention).where(EntityMention.article_id == article.id))
        self.session.execute(delete(Claim).where(Claim.article_id == article.id))
        self.session.execute(delete(Relationship).where(Relationship.article_id == article.id))
        self.session.execute(
            delete(AttackMapping).where(
                AttackMapping.parent_type == "article", AttackMapping.parent_id == article.id
            )
        )
        self.session.execute(
            delete(AnalystReview).where(
                AnalystReview.article_id == article.id,
                AnalystReview.item_type == "claim",
                AnalystReview.status == "open",
            )
        )

    def _closed_claim_review(self, article_id: int, evidence_text: str) -> AnalystReview | None:
        return self.session.scalar(
            select(AnalystReview)
            .where(
                AnalystReview.item_type == "claim",
                AnalystReview.article_id == article_id,
                AnalystReview.status != "open",
                AnalystReview.evidence_text == evidence_text,
            )
            .order_by(AnalystReview.id.desc())
            .limit(1)
        )

    def _add_review_once(self, **fields) -> None:
        """Route to the review queue unless an OPEN review for the same
        (item_type, item_id) already exists — reprocessing must not pile up
        duplicate open reviews for the same item."""
        existing = self.session.scalar(
            select(AnalystReview).where(
                AnalystReview.item_type == fields["item_type"],
                AnalystReview.item_id == fields["item_id"],
                AnalystReview.status == "open",
            )
        )
        if existing is None:
            self.session.add(AnalystReview(**fields))

    def _source_hosts(self) -> set[str]:
        """Hosts of configured sources: links back to them are citations."""
        from urllib.parse import urlsplit

        from scry.models import Source

        hosts: set[str] = set()
        for url, feed in self.session.execute(select(Source.url, Source.feed)).all():
            for value in (url, feed):
                host = (urlsplit(value or "").hostname or "").lower()
                if host.startswith("www."):
                    host = host[4:]
                if host and "." in host:
                    hosts.add(host)
        return hosts

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")

    def _context_tags(self, article: Article, result: ExtractionResult) -> list[str]:
        """Source provenance tags shared by every IOC in the article."""
        tags: set[str] = set()
        source = article.source
        if source is not None:
            tags.update(source.tags or [])
            source_slug = self._slug(source.name)
            if source_slug:
                tags.add(f"source:{source_slug}")
            type_slug = self._slug(source.type)
            if type_slug:
                tags.add(f"source-type:{type_slug}")
        return sorted(tags)

    def _entity_tag_patterns(self, result: ExtractionResult) -> list[tuple[re.Pattern[str], list[str]]]:
        """(pattern over the entity's names, tags to add) per extracted entity."""
        out: list[tuple[re.Pattern[str], list[str]]] = []
        for ent in result.entities:
            canonical, _ = resolve_canonical(ent.surface_form, ent.type)
            slug = self._slug(canonical)
            if not slug:
                continue
            kind = self._slug(ent.type)
            tags = [f"{kind}:{slug}"]
            if ent.type == "threat_actor":
                tags.append(f"actor:{slug}")
            elif ent.type == "malware_family":
                tags.append(f"malware:{slug}")
            names = sorted({ent.surface_form, canonical}, key=len, reverse=True)
            patt = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names if n) + r")\b", re.IGNORECASE)
            out.append((patt, tags))
        return out

    def _upsert_observable(self, ioc: IOCCandidate, article: Article) -> Observable:
        ob = self.session.scalar(
            select(Observable).where(
                Observable.type == ioc.type, Observable.normalized_value == ioc.normalized_value
            )
        )
        now = datetime.now(UTC)
        if ob is None:
            ob = Observable(
                type=ioc.type,
                value=ioc.value,
                normalized_value=ioc.normalized_value,
                defanged_value=ioc.defanged_value,
                validation_status="valid",
                extraction_confidence=ioc.extraction_confidence,
                maliciousness_confidence=ioc.maliciousness_confidence,
                false_positive_risk=ioc.false_positive_risk,
                first_seen=now,
                last_seen=now,
                first_reported=article.published_at or now,
                last_reported=article.published_at or now,
                tags=list(ioc.tags),
                scoring_model_version=SCORING_MODEL_VERSION,
            )
            self.session.add(ob)
            self.session.flush()
        else:
            ob.last_seen = now
            # Never move last_reported backwards: re-ingesting an older
            # article must not erase a newer sighting. (SQLite round-trips
            # datetimes as naive, so normalize before comparing.)
            new_reported = _as_utc(article.published_at or now)
            if ob.last_reported is None or new_reported > _as_utc(ob.last_reported):
                ob.last_reported = new_reported
            ob.extraction_confidence = max(ob.extraction_confidence, ioc.extraction_confidence)
            # Local evidence from this sighting can raise (never lower) the
            # stored maliciousness / false-positive signals.
            ob.maliciousness_confidence = max(ob.maliciousness_confidence, ioc.maliciousness_confidence)
            ob.false_positive_risk = max(ob.false_positive_risk or 0.0, ioc.false_positive_risk)
            ob.tags = sorted(set([*ob.tags, *ioc.tags]))

        self.session.add(
            ObservableMention(
                observable_id=ob.id,
                article_id=article.id,
                evidence_text=ioc.evidence_text,
                context_window=ioc.context_window,
                extraction_method=ioc.extraction_method,
                extraction_confidence=ioc.extraction_confidence,
            )
        )
        return ob

    def _enrich_and_score(self, ob: Observable, ioc: IOCCandidate, article: Article) -> None:
        try:
            self.enrichment.enrich_observable(ob, evidence_text=ioc.evidence_text)
        except Exception as exc:
            logger.warning(
                "enrich_error", ob_id=ob.id, ob_type=ob.type, value=ob.normalized_value[:60], exc=str(exc)
            )

        confidence = self.confidence.score(
            ConfidenceInputs(
                source_confidence=article.source_confidence,
                extraction_confidence=ob.extraction_confidence,
                enrichment_confidence=60,
                maliciousness_confidence=ob.maliciousness_confidence,
                attribution_confidence=50,
                independent_source_count=max(
                    1, (ob.enrichment or {}).get("prevalence", {}).get("distinct_sources", 1)
                ),
            )
        )

        enrichment = ob.enrichment or {}
        local_topics = {
            t.tag
            for t in classify_all(
                local_context(ioc.context_window or ioc.evidence_text or "", ioc.value, ioc.normalized_value)
            )
        }
        risk = self.risk.score(
            RiskInputs(
                maliciousness_confidence=ob.maliciousness_confidence,
                source_confidence=article.source_confidence,
                recency_days=recency_days(article.published_at),
                independent_sources=enrichment.get("prevalence", {}).get("distinct_sources", 1),
                attached_topics=set(article.tags or []),
                benign_context_flags=[
                    *(t for t in (ob.tags or []) if "benign" in t or t in BENIGN_CONTEXT_TAGS),
                    *vendor_clean_flags(enrichment),
                ],
                enrichment=enrichment,
                local_topics=local_topics,
                ioc_type=ob.type,
                corroborating_flags=[k for k in enrichment if k.endswith("_escalated")],
            )
        )
        ob.risk_score = risk.score
        ob.actionability = risk.actionability
        # Keep the arithmetic next to the number so the UI can explain it.
        ob.enrichment = {
            **enrichment,
            "risk_breakdown": {
                "score": risk.score,
                "model_version": risk.model_version,
                "article_id": article.id,
                "contributors": [[name, round(float(value), 1)] for name, value in risk.contributors],
            },
        }
        ob.maliciousness_confidence = confidence.maliciousness_confidence
        ob.ttl_days = self.lifecycle.ttl_for(ob)
        if ob.ttl_days > 0:
            ob.expiration_date = expiration_from_ttl(ob.ttl_days, ob.last_reported)

    def _maybe_route_observable_to_review(self, ob: Observable, ioc: IOCCandidate, article: Article) -> None:
        if ob.actionability not in {"urgent_review", "block_if_safe"}:
            return
        # Block-if-safe candidates that hit benign infrastructure → review queue.
        if (ob.enrichment or {}).get("benign_shared_infrastructure") or "benign-shared-infrastructure" in (
            ob.tags or []
        ):
            self._add_review_once(
                item_type="observable",
                item_id=ob.id,
                reason="High risk score but benign shared infrastructure context",
                confidence=ob.maliciousness_confidence,
                article_id=article.id,
                evidence_text=ioc.evidence_text,
                recommended_action="human_review",
            )

    def _persist_relationships(self, rels: list[RelationshipCandidate], article: Article) -> None:
        for r in rels:
            src_id = self._lookup_object_id(r.source_type, r.source_value)
            tgt_id = self._lookup_object_id(r.target_type, r.target_value)
            if src_id is None or tgt_id is None:
                continue
            self.session.add(
                Relationship(
                    source_type=r.source_type,
                    source_id=src_id,
                    target_type=r.target_type,
                    target_id=tgt_id,
                    relationship_type=r.relationship_type,
                    confidence=r.confidence,
                    # Belt and braces: any extractor (incl. a future LLM one)
                    # may hand back a huge sentence — cap it at the sink too.
                    evidence_text=evidence_window(r.evidence_text, [[r.source_value], [r.target_value]]),
                    article_id=article.id,
                    explicit_or_inferred=r.explicit_or_inferred,
                    extraction_method=r.extraction_method,
                    extractor_version=EXTRACTOR_VERSION,
                )
            )

    def _lookup_object_id(self, kind: str, value: str) -> int | None:
        if kind in {"threat_actor", "malware_family", "tool", "campaign"}:
            ent = self.session.scalar(
                select(Entity).where(Entity.type == kind, Entity.canonical_name == value)
            )
            return ent.id if ent else None
        # IOC types
        ob = self.session.scalar(
            select(Observable).where(Observable.type == kind, Observable.normalized_value == value)
        )
        return ob.id if ob else None


# ---------------------------------------------------------------------------
# Bulk reprocessing (scoring model 0.2)
# ---------------------------------------------------------------------------

# Tags the pipeline derives from article context; rebuilt on every reprocess.
_DERIVED_TAG_PREFIXES = ("threat-actor:", "actor:", "malware-family:", "malware:")
_DERIVED_TAGS = frozenset({"malicious-context", "possible-filename", "victim-context", "reference-context"})
RETRACTED_TAG = "retracted-by-extractor"


def reprocess_articles(session: Session, article_ids: list[int]) -> dict[str, int]:
    """Re-run extraction + scoring for ``article_ids`` with the current rules.

    Before re-extraction, context-derived tags and the maliciousness / false-
    positive signals of the observables these articles mention are reset, so
    stale attributions (a roundup's actor stamped on every CVE) and stale
    scores do not survive the merge. Observables that no longer appear in any
    article after the rerun (e.g. ``asp.net``, a product name the extractor
    now rejects) are retracted: status ``false_positive``, risk 0, tagged
    ``retracted-by-extractor``. Nothing is deleted.
    """
    if not article_ids:
        return {"articles": 0, "observables_rescored": 0, "observables_retracted": 0}
    touched: set[int] = set()
    for chunk in _chunks(article_ids):
        touched.update(
            session.scalars(
                select(ObservableMention.observable_id).where(ObservableMention.article_id.in_(chunk))
            ).all()
        )
    for chunk in _chunks(sorted(touched)):
        for ob in session.scalars(select(Observable).where(Observable.id.in_(chunk))):
            ob.tags = [
                t
                for t in (ob.tags or [])
                if t not in _DERIVED_TAGS and not t.startswith(_DERIVED_TAG_PREFIXES)
            ]
            ob.maliciousness_confidence = 50
            ob.false_positive_risk = 0.0
    session.commit()

    pipeline = CTIPipeline(session)
    done = 0
    for article_id in article_ids:
        article = session.get(Article, article_id)
        if article is None:
            continue
        article.extractor_version = "0"
        try:
            pipeline.process_article(article)
            done += 1
        except Exception as exc:  # keep going; one bad article must not stop a rebuild
            session.rollback()
            logger.warning("reprocess_failed", article_id=article_id, exc=str(exc))

    still_mentioned: set[int] = set()
    for chunk in _chunks(sorted(touched)):
        still_mentioned.update(
            session.scalars(
                select(ObservableMention.observable_id).where(ObservableMention.observable_id.in_(chunk))
            ).all()
        )
    retracted = 0
    for chunk in _chunks(sorted(touched - still_mentioned)):
        for ob in session.scalars(select(Observable).where(Observable.id.in_(chunk))):
            ob.status = "false_positive"
            ob.risk_score = 0.0
            ob.actionability = "enrich_only"
            ob.tags = sorted({*(ob.tags or []), RETRACTED_TAG})
            retracted += 1
    session.commit()
    return {
        "articles": done,
        "observables_rescored": len(still_mentioned),
        "observables_retracted": retracted,
    }


def _chunks(ids: list[int], size: int = 500):
    """Slices small enough for SQLite's bound-variable limit."""
    for i in range(0, len(ids), size):
        yield ids[i : i + size]
