"""Source reliability scoring.

Combines the baseline reliability from the source profile with a running
accuracy metric that analysts can adjust via review dispositions.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Source, SourceReliabilityProfile


class SourceReliabilityScorer:
    def __init__(self, session: Session) -> None:
        self.session = session

    def score(self, source_id: int) -> int:
        profile = self.session.scalar(
            select(SourceReliabilityProfile).where(SourceReliabilityProfile.source_id == source_id)
        )
        source = self.session.get(Source, source_id)
        baseline = profile.baseline_reliability if profile else (source.baseline_confidence if source else 60)
        accuracy_adj = int((profile.historical_accuracy - 0.75) * 40) if profile else 0
        fp_penalty = int((profile.false_positive_rate - 0.1) * -50) if profile else 0
        sensationalism_penalty = int(-profile.sensationalism_score * 10) if profile else 0
        bonus = 10 if profile and profile.original_research_ratio > 0.7 else 0
        aggregator_penalty = -10 if profile and profile.is_aggregator else 0
        score = baseline + accuracy_adj + fp_penalty + sensationalism_penalty + bonus + aggregator_penalty
        return max(0, min(100, score))
