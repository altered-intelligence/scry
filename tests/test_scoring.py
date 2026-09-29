from scry.scoring.confidence import ConfidenceInputs, ConfidenceScorer
from scry.scoring.risk import RiskInputs, RiskScorer


def test_confidence_blends_factors():
    s = ConfidenceScorer().score(
        ConfidenceInputs(
            source_confidence=90,
            extraction_confidence=80,
            maliciousness_confidence=70,
            attribution_confidence=60,
            enrichment_confidence=70,
            relationship_confidence=70,
            independent_source_count=3,
        )
    )
    assert 60 <= s.overall_confidence <= 100


def test_risk_increases_with_kev_and_microsoft():
    base = RiskScorer().score(
        RiskInputs(
            maliciousness_confidence=60,
            source_confidence=80,
            recency_days=5,
            independent_sources=1,
            attached_topics={"microsoft"},
            benign_context_flags=[],
            enrichment={"kev": True, "ransomware_associated": True, "public_poc_available": True},
        )
    )
    assert base.score >= 80
    assert base.actionability in {"urgent_review", "block_if_safe"}


def test_risk_drops_on_benign_infrastructure():
    s = RiskScorer().score(
        RiskInputs(
            maliciousness_confidence=80,
            source_confidence=80,
            recency_days=5,
            independent_sources=2,
            attached_topics={"ransomware"},
            benign_context_flags=[],
            enrichment={"benign_shared_infrastructure": True},
        )
    )
    assert s.actionability == "monitor"
    assert any(name == "benign_shared_infrastructure" for name, _ in s.contributors)
