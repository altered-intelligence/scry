from datetime import UTC, datetime

from scry.conflicts import detect_conflicts
from scry.models import Article, Claim


def test_detects_attribution_disagreement(session, seed_source):
    art1 = Article(
        source_id=seed_source.id,
        url="https://example.com/v1",
        extracted_text="...",
        ingested_at=datetime.now(UTC),
    )
    art2 = Article(
        source_id=seed_source.id,
        url="https://example.com/v2",
        extracted_text="...",
        ingested_at=datetime.now(UTC),
    )
    session.add_all([art1, art2])
    session.commit()
    # Shared evidence wording so the overlap heuristic fires, but different actor names.
    shared_evidence = (
        "The Acme Aerospace targeting campaign exploiting Edge Gateway against contractors observed broadly"
    )
    session.add_all(
        [
            Claim(
                article_id=art1.id,
                claim_type="attribution",
                claim_text="attributed to APT28",
                evidence_text=shared_evidence + " APT28",
            ),
            Claim(
                article_id=art2.id,
                claim_type="attribution",
                claim_text="attributed to APT29",
                evidence_text=shared_evidence + " APT29",
            ),
        ]
    )
    session.commit()
    new = detect_conflicts(session)
    assert any(c.conflict_type == "attribution_disagreement" for c in new)
