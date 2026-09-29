from scry.deduplication import find_duplicate_article
from scry.models import Article


def test_dedup_by_url(session, seed_source):
    art = Article(source_id=seed_source.id, title="x", url="https://example.com/a", extracted_text="")
    session.add(art)
    session.commit()
    dup = find_duplicate_article(session, url="https://example.com/a")
    assert dup is not None and dup.id == art.id


def test_dedup_by_content_hash(session, seed_source):
    art = Article(source_id=seed_source.id, title="x", url="https://example.com/b", content_hash="abc123")
    session.add(art)
    session.commit()
    dup = find_duplicate_article(session, url="https://example.com/different", content_hash="abc123")
    assert dup is not None and dup.id == art.id
