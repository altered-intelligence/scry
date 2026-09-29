from datetime import UTC, datetime

from scry.models import Article
from scry.search import full_text_search, semantic_search


def test_full_text_search_finds_article(session, seed_source):
    a = Article(
        source_id=seed_source.id,
        title="Ransomware report on Acme",
        url="https://example.com/a",
        extracted_text="LockBit deployed ransomware against Acme",
        ingested_at=datetime.now(UTC),
    )
    session.add(a)
    session.commit()
    hits = full_text_search(session, "lockbit", limit=10)
    assert any(h.object_type == "article" and h.object_id == a.id for h in hits)


def test_semantic_search_returns_ranked_hits(session, seed_source):
    for i, body in enumerate(
        [
            "Ransomware against healthcare",
            "Quantum computing breakthrough",
            "Wiper deployed in geopolitical conflict",
        ]
    ):
        session.add(
            Article(
                source_id=seed_source.id,
                title=body[:30],
                url=f"https://example.com/{i}",
                extracted_text=body,
                ingested_at=datetime.now(UTC),
            )
        )
    session.commit()
    hits = semantic_search(session, "ransomware in hospitals", target="articles", limit=3)
    assert hits and hits[0].snippet.lower().startswith("ransomware")
