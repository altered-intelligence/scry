from scry.models import Article
from scry.review.routing import should_route_observable, should_route_to_review
from scry.schemas.extraction import ClaimCandidate, IOCCandidate


def test_attribution_routes_to_review(seed_source):
    art = Article(source_id=seed_source.id, title="x", url="https://example.com/a")
    claim = ClaimCandidate(
        claim_text="attributed to APT28",
        claim_type="attribution",
        evidence_text="attributed to APT28",
        confidence=70,
    )
    assert should_route_to_review(claim, art)


def test_low_confidence_routes(seed_source):
    art = Article(source_id=seed_source.id, title="x", url="https://example.com/b")
    claim = ClaimCandidate(
        claim_text="something happened",
        claim_type="exploited_in_the_wild",
        evidence_text="...",
        confidence=40,
    )
    assert should_route_to_review(claim, art)


def test_benign_high_confidence_observable_routes():
    ioc = IOCCandidate(
        type="domain",
        value="github.com",
        normalized_value="github.com",
        tags=["benign-shared-infrastructure"],
        maliciousness_confidence=80,
        extraction_confidence=80,
    )
    assert should_route_observable(ioc)
