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

logger = get_logger("pipeline")


def _as_utc(dt: datetime) -> datetime:
    """Treat naive datetimes (SQLite round-trip) as UTC for safe comparison."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class CTIPipeline:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.extractor = Extractor()
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

        # Propagate article/source/entity context onto every extracted IOC
        # so downstream search and scoring can see provenance and attribution.
        context_tags = self._context_tags(article, result)

        # Persist observables and mentions.
        for ioc in result.iocs:
            ioc.tags = sorted(set([*ioc.tags, *context_tags]))
            ob = self._upsert_observable(ioc, article)
            self._enrich_and_score(ob, ioc, article)
            self._maybe_route_observable_to_review(ob, ioc, article)

        # Persist entities and mentions.
        for ent in result.entities:
            entity = upsert_entity(
                self.session,
                surface_form=ent.surface_form,
                entity_type=ent.type,
            )
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
            if row.needs_review:
                row.review_status = "pending"
            self.session.add(row)
            self.session.flush()
            if row.needs_review:
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
        return result

    # -------- helpers --------

    def _clear_derived_rows(self, article: Article) -> None:
        """Delete extraction products of a prior run for this article.

        Observables themselves are upserted (shared across articles) so they
        survive; only per-article rows are rebuilt. Open auto-routed claim
        reviews for this article would dangle once their claims are replaced,
        so they are dropped too — reviews an analyst already touched are kept
        as an audit trail.
        """
        self.session.execute(delete(ObservableMention).where(ObservableMention.article_id == article.id))
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

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")

    def _context_tags(self, article: Article, result: ExtractionResult) -> list[str]:
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
        for ent in result.entities:
            canonical, _ = resolve_canonical(ent.surface_form, ent.type)
            slug = self._slug(canonical)
            if not slug:
                continue
            kind = self._slug(ent.type)
            tags.add(f"{kind}:{slug}")
            if ent.type == "threat_actor":
                tags.add(f"actor:{slug}")
            elif ent.type == "malware_family":
                tags.add(f"malware:{slug}")
        return sorted(tags)

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

        risk = self.risk.score(
            RiskInputs(
                maliciousness_confidence=ob.maliciousness_confidence,
                source_confidence=article.source_confidence,
                recency_days=recency_days(article.published_at),
                independent_sources=(ob.enrichment or {}).get("prevalence", {}).get("distinct_sources", 1),
                attached_topics=set(article.tags or []),
                benign_context_flags=[t for t in (ob.tags or []) if "benign" in t],
                enrichment=ob.enrichment or {},
            )
        )
        ob.risk_score = risk.score
        ob.actionability = risk.actionability
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
                    evidence_text=r.evidence_text,
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
