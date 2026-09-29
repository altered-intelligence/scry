"""Risk and actionability scoring.

Transparent contributor list (factor name + value) so analysts can audit
why an IOC is being flagged urgent vs. monitor. Benign-context flags shave
points and downgrade the recommended action.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from scry.schemas.scoring import RiskScore


@dataclass
class RiskInputs:
    maliciousness_confidence: int
    source_confidence: int
    recency_days: int | None
    independent_sources: int
    attached_topics: set[str]
    benign_context_flags: list[str]
    enrichment: dict[str, Any]


class RiskScorer:
    MODEL_VERSION = "0.1"

    def score(self, inputs: RiskInputs) -> RiskScore:
        contributors: list[tuple[str, float]] = []

        # Core: maliciousness x source
        base = (inputs.maliciousness_confidence * 0.4) + (inputs.source_confidence * 0.2)
        contributors.append(("maliciousness", inputs.maliciousness_confidence * 0.4))
        contributors.append(("source_confidence", inputs.source_confidence * 0.2))

        # Recency
        if inputs.recency_days is not None:
            if inputs.recency_days <= 7:
                contributors.append(("recency<=7d", 10))
                base += 10
            elif inputs.recency_days > 180:
                contributors.append(("recency>180d", -15))
                base -= 15

        # Corroboration
        if inputs.independent_sources >= 2:
            contributors.append(("multi_source", 10))
            base += 10

        # Topic-driven contributors
        for topic, bump in (
            ("ransomware", 20),
            ("wiper", 20),
            ("exploited-in-the-wild", 25),
            ("defense-industry", 15),
            ("microsoft", 10),
            ("exploit-poc", 10),
            ("appdomainmanager-hijacking", 10),
            ("ai-security", 5),
        ):
            if topic in inputs.attached_topics:
                contributors.append((f"topic:{topic}", bump))
                base += bump

        # KEV / patch_available
        if inputs.enrichment.get("kev"):
            contributors.append(("kev", 25))
            base += 25
        if inputs.enrichment.get("ransomware_associated"):
            contributors.append(("ransomware_associated_cve", 15))
            base += 15
        if inputs.enrichment.get("public_poc_available"):
            contributors.append(("public_poc", 10))
            base += 10

        # Benign-context guardrails
        flag_penalty = 0
        for flag in inputs.benign_context_flags:
            flag_penalty -= 20
            contributors.append((f"benign_context:{flag}", -20))
        if inputs.enrichment.get("benign_shared_infrastructure"):
            flag_penalty -= 20
            contributors.append(("benign_shared_infrastructure", -20))
        if inputs.enrichment.get("likely_cloud_or_cdn"):
            flag_penalty -= 10
            contributors.append(("likely_cloud_or_cdn", -10))
        if inputs.enrichment.get("url_shortener"):
            flag_penalty -= 10
            contributors.append(("url_shortener", -10))
        base += flag_penalty

        score = max(0.0, min(100.0, float(base)))
        action = self._actionability(score, inputs)
        return RiskScore(
            score=score,
            actionability=action,
            contributors=contributors,
            benign_context_flags=list(inputs.benign_context_flags),
            model_version=self.MODEL_VERSION,
        )

    def _actionability(self, score: float, inputs: RiskInputs) -> str:
        if any(
            inputs.enrichment.get(k)
            for k in ("benign_shared_infrastructure", "likely_cloud_or_cdn", "url_shortener")
        ):
            return "monitor"
        if score >= 85:
            return "urgent_review"
        if score >= 70:
            return "block_if_safe"
        if score >= 55:
            return "high_priority_hunt"
        if score >= 30:
            return "monitor"
        return "enrich_only"


def recency_days(timestamp: datetime | None) -> int | None:
    if timestamp is None:
        return None
    now = datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return max(0, (now - timestamp).days)


def expiration_from_ttl(ttl_days: int, start: datetime | None = None) -> datetime:
    start = start or datetime.now(UTC)
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    return start + timedelta(days=ttl_days)
