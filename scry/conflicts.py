"""Conflict detection between claims.

Detects pairs of claims that contradict each other across different
articles. The system preserves both claims — it does not overwrite — and
routes the conflict to analyst review.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Claim, Conflict


def detect_conflicts(session: Session) -> list[Conflict]:
    """Scan the claim table and create Conflict rows for contradictory pairs."""
    by_type: defaultdict[str, list[Claim]] = defaultdict(list)
    for claim in session.scalars(select(Claim)):
        by_type[claim.claim_type].append(claim)

    out: list[Conflict] = []
    # Seed with pairs already recorded so repeat runs don't duplicate rows.
    seen: set[tuple[int, int]] = set(session.execute(select(Conflict.claim_a_id, Conflict.claim_b_id)).all())

    # Multiple attributions for visibly overlapping evidence → mark for review.
    for attr_claim in by_type.get("attribution", []):
        for other in by_type.get("attribution", []):
            if other.id <= attr_claim.id:
                continue
            if _evidence_overlaps(
                attr_claim.evidence_text, other.evidence_text
            ) and not _likely_same_attribution(attr_claim.claim_text, other.claim_text):
                key = (attr_claim.id, other.id)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    Conflict(
                        claim_a_id=attr_claim.id,
                        claim_b_id=other.id,
                        conflict_type="attribution_disagreement",
                        recommended_review_reason="Two articles attribute the same activity to different actors",
                    )
                )

    if out:
        session.add_all(out)
        session.commit()
    return out


def _evidence_overlaps(a: str, b: str, *, min_shared_tokens: int = 5) -> bool:
    ta = {t for t in (a or "").lower().split() if len(t) > 3}
    tb = {t for t in (b or "").lower().split() if len(t) > 3}
    return len(ta & tb) >= min_shared_tokens


# Capitalized words that carry no attribution meaning — a shared one of these
# must not count as "same actor". Sentence openers and reporting boilerplate.
_ATTRIBUTION_STOPWORDS = {
    "The",
    "This",
    "That",
    "These",
    "Those",
    "A",
    "An",
    "In",
    "On",
    "At",
    "It",
    "According",
    "Researchers",
    "Analysts",
    "Security",
    "Report",
    "Reports",
    "New",
}


def _likely_same_attribution(a: str, b: str) -> bool:
    # Cheap heuristic — if both claims share a proper noun, treat as agreement.
    # Stopword-filtered so a shared sentence opener ("The …") isn't a match.
    a_caps = {w for w in a.split() if w[:1].isupper()} - _ATTRIBUTION_STOPWORDS
    b_caps = {w for w in b.split() if w[:1].isupper()} - _ATTRIBUTION_STOPWORDS
    return len(a_caps & b_caps) >= 1
