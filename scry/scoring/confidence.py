"""Confidence scoring.

Multi-factor breakdown so analysts can see WHY a score is what it is.
Composes source confidence, extraction confidence, enrichment outcomes,
attribution, and corroboration count.
"""

from __future__ import annotations

from dataclasses import dataclass

from scry.schemas.scoring import ConfidenceBreakdown


@dataclass
class ConfidenceInputs:
    source_confidence: int
    extraction_confidence: int
    relationship_confidence: int = 0
    enrichment_confidence: int = 0
    maliciousness_confidence: int = 50
    attribution_confidence: int = 50
    independent_source_count: int = 1
    aggregator: bool = False


class ConfidenceScorer:
    MODEL_VERSION = "0.1"

    def score(self, inputs: ConfidenceInputs) -> ConfidenceBreakdown:
        rationale: list[str] = []
        srcs = max(1, inputs.independent_source_count)
        corroboration_bonus = min(20, (srcs - 1) * 5)
        if corroboration_bonus:
            rationale.append(f"+{corroboration_bonus} for {srcs} independent sources")
        aggregator_penalty = -5 if inputs.aggregator else 0
        if aggregator_penalty:
            rationale.append("-5 for aggregator-only sourcing")

        overall = (
            (
                inputs.source_confidence * 0.30
                + inputs.extraction_confidence * 0.25
                + inputs.maliciousness_confidence * 0.20
                + inputs.attribution_confidence * 0.10
                + inputs.enrichment_confidence * 0.10
                + inputs.relationship_confidence * 0.05
            )
            + corroboration_bonus
            + aggregator_penalty
        )
        overall = int(max(0, min(100, overall)))

        return ConfidenceBreakdown(
            source_confidence=inputs.source_confidence,
            extraction_confidence=inputs.extraction_confidence,
            relationship_confidence=inputs.relationship_confidence,
            enrichment_confidence=inputs.enrichment_confidence,
            maliciousness_confidence=inputs.maliciousness_confidence,
            attribution_confidence=inputs.attribution_confidence,
            overall_confidence=overall,
            rationale=rationale,
        )
