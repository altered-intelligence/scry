"""Routing rules for the analyst review queue.

Rules implement what the spec says: route to review when confidence is low,
attribution is weak/disputed, claim involves nation-state activity, ransomware
victim naming, active exploitation, dark web material, exploit code, etc.
"""

from __future__ import annotations

from scry.models import Article
from scry.schemas.extraction import ClaimCandidate, IOCCandidate

_REVIEW_REQUIRED_TYPES = {
    "attribution",
    "victim_claimed",
    "exploited_in_the_wild",
    "wiper_deployment",
    "supply_chain_compromise",
    "appdomainmanager_hijacking",
    "ransomware_deployment",
    "targets_defense_industry",
}

_NATION_STATE_HINTS = (
    "nation-state",
    "nation state",
    "state-sponsored",
    "apt",
    "russia",
    "china",
    "iran",
    "north korea",
    "dprk",
)


def should_route_to_review(claim: ClaimCandidate, article: Article) -> bool:
    if claim.confidence < 60:
        return True
    if claim.claim_type in _REVIEW_REQUIRED_TYPES:
        return True
    text = (claim.evidence_text or "").lower()
    if any(h in text for h in _NATION_STATE_HINTS):
        return True
    return "exploit" in text and "released" in text


def should_route_observable(ioc: IOCCandidate) -> bool:
    if ioc.false_positive_risk >= 0.7:
        return True
    return "benign-shared-infrastructure" in ioc.tags and ioc.maliciousness_confidence >= 60
