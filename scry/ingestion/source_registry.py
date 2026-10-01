"""Source registry — load YAML into DB and provide lookup helpers."""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.config import load_sources
from scry.logging import get_logger
from scry.models import Source, SourceReliabilityProfile

logger = get_logger("source_registry")


class SourceRegistry:
    def __init__(self, session: Session) -> None:
        self.session = session

    def sync_from_yaml(self) -> dict[str, int]:
        """Upsert all sources defined in config/sources.yaml. Returns counts."""
        added, updated = 0, 0
        for spec in load_sources():
            name = spec["name"]
            existing = self.session.scalar(select(Source).where(Source.name == name))
            if existing is None:
                src = Source(
                    name=name,
                    type=spec.get("type", "unknown"),
                    url=spec.get("url", ""),
                    feed=spec.get("feed"),
                    enabled=bool(spec.get("enabled", False)),
                    priority=spec.get("priority", "medium"),
                    baseline_confidence=int(spec.get("baseline_confidence", 60)),
                    collection_policy=spec.get("collection_policy", "safe_public_web"),
                    safety_mode=spec.get("safety_mode"),
                    independent=bool(spec.get("independent", False)),
                    rate_limit_per_minute=int(spec.get("rate_limit_per_minute", 10)),
                    tags=spec.get("tags", []),
                    notes=spec.get("notes"),
                )
                self.session.add(src)
                self.session.flush()
                self.session.add(
                    SourceReliabilityProfile(
                        source_id=src.id,
                        category=spec.get("type", "news"),
                        baseline_reliability=int(spec.get("baseline_confidence", 60)),
                        is_aggregator=spec.get("type") in {"aggregator", "newsletter"},
                    )
                )
                added += 1
            else:
                existing.type = spec.get("type", existing.type)
                existing.url = spec.get("url", existing.url)
                existing.feed = spec.get("feed", existing.feed)
                # ``enabled`` is RUNTIME STATE managed from the Sources page
                # (/ui/sources, admin-only toggles). The yaml value applies
                # only when the row is first created; re-syncing here would
                # clobber admin toggles on every restart (v0.7.0 step 1).
                existing.priority = spec.get("priority", existing.priority)
                existing.baseline_confidence = int(
                    spec.get("baseline_confidence", existing.baseline_confidence)
                )
                existing.collection_policy = spec.get("collection_policy", existing.collection_policy)
                existing.safety_mode = spec.get("safety_mode", existing.safety_mode)
                existing.independent = bool(spec.get("independent", existing.independent))
                existing.rate_limit_per_minute = int(
                    spec.get("rate_limit_per_minute", existing.rate_limit_per_minute)
                )
                existing.tags = spec.get("tags", existing.tags)
                existing.notes = spec.get("notes", existing.notes)
                updated += 1
        self.session.commit()
        logger.info("sources_synced", added=added, updated=updated)
        return {"added": added, "updated": updated}

    def enabled_sources(self) -> Iterable[Source]:
        return self.session.scalars(select(Source).where(Source.enabled.is_(True))).all()

    def get(self, name: str) -> Source | None:
        return self.session.scalar(select(Source).where(Source.name == name))

    def get_by_id(self, source_id: int) -> Source | None:
        return self.session.get(Source, source_id)
