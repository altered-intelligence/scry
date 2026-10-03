"""Persisted-embedding tests (v0.12.0): backfill, query path, parity, hooks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest
from sqlalchemy import event, select

import scry.ingestion.ingest_engine as ingest_engine_module
import scry.search.embeddings as emb
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.models import Article, ArticleEmbedding
from scry.pipeline import CTIPipeline
from scry.search.embeddings import embed
from scry.search.semantic import semantic_search


def _article(session, source, url: str, *, title: str = "t", text: str = "", summary: str = "") -> Article:
    art = Article(
        source_id=source.id,
        title=title,
        url=url,
        ingested_at=datetime.now(UTC),
        published_at=datetime.now(UTC),
        extracted_text=text,
        summary=summary,
    )
    session.add(art)
    session.commit()
    return art


def _old_scores(session, q: str) -> list[tuple[float, int]]:
    from scry.search.semantic import _cosine

    qvec = embed(q)
    scored = []
    for art in session.scalars(select(Article)):
        text = emb.article_text(art.title, art.summary, art.extracted_text)
        scored.append((_cosine(qvec, embed(text)), art.id))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


CORPUS = [
    ("Ransomware hits hospitals", "LockBit affiliates breached three US hospitals using phishing emails."),
    ("Cloud costs soar", "Enterprise cloud spending rose sharply as GPU demand outpaced supply."),
    ("CVE-2024-3980 exploited", "Hitachi Energy FACTS control platform RCE exploited in the wild."),
    ("Hospital phishing wave", "Healthcare providers report credential phishing campaigns this quarter."),
    ("Coffee prices steady", "Global coffee futures held steady amid balanced supply forecasts."),
]


def _seed_corpus(session, source) -> list[Article]:
    return [
        _article(session, source, f"https://example.com/e{i}", title=t, text=x)
        for i, (t, x) in enumerate(CORPUS)
    ]


class TestBackfill:
    def test_backfill_idempotent_and_complete(self, session, seed_source):
        arts = _seed_corpus(session, seed_source)
        n = emb.backfill_embeddings(session.connection())
        assert n == len(arts)
        assert session.scalar(select(ArticleEmbedding).limit(1)) is not None
        count = len(session.scalars(select(ArticleEmbedding)).all())
        assert count == len(arts)
        # Second pass: hashes all match → nothing re-embedded.
        assert emb.backfill_embeddings(session.connection()) == 0

    def test_backfill_picks_up_text_changes(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/c1", text="first wording")
        assert emb.backfill_embeddings(session.connection()) == 1
        art.extracted_text = "completely different secondtext"
        session.commit()
        assert emb.backfill_embeddings(session.connection()) == 1  # re-embedded
        assert emb.backfill_embeddings(session.connection()) == 0  # stable again

    def test_empty_db(self, session):
        assert emb.backfill_embeddings(session.connection()) == 0
        assert semantic_search(session, "ransomware", limit=5) == []


class TestRankingParity:
    def test_new_path_matches_legacy_ordering(self, session, seed_source):
        arts = _seed_corpus(session, seed_source)
        emb.backfill_embeddings(session.connection())

        q = "ransomware hospitals phishing"
        hits = semantic_search(session, q, limit=10)
        new_ids = [h.object_id for h in hits]
        old_ids = [rid for _, rid in _old_scores(session, q)]
        assert new_ids == old_ids
        assert len(new_ids) == len(arts)
        # Same scores, too (float32 storage tolerance).
        old_map = {rid: score for score, rid in _old_scores(session, q)}
        for h in hits:
            assert h.score == pytest.approx(old_map[h.object_id], abs=1e-6)


class TestQueryPath:
    def test_query_does_not_scan_article_bodies(self, session, seed_source):
        _seed_corpus(session, seed_source)
        emb.backfill_embeddings(session.connection())
        session.commit()

        stmts: list[str] = []
        engine = session.get_bind()

        def _capture(conn, cursor, statement, parameters, context, executemany):
            stmts.append(statement)

        event.listen(engine, "before_cursor_execute", _capture)
        try:
            hits = semantic_search(session, "ransomware hospitals", limit=2)
        finally:
            event.remove(engine, "before_cursor_execute", _capture)
        assert len(hits) == 2
        # The ONLY statement reading body columns is the bounded top-k fetch.
        body_reads = [s for s in stmts if "extracted_text" in s]
        assert len(body_reads) == 1
        assert " IN " in body_reads[0]
        # Exactly one statement scans the embeddings table as its main source
        # (the id+blob vector load); everything else is id-only or the top-k IN.
        main_sources = [s.split("FROM", 1)[1].lstrip().split()[0] for s in stmts if "FROM" in s]
        assert main_sources.count("article_embeddings") == 1
        assert main_sources.count("articles") == 2  # missing-id check + top-k fetch

    def test_straggler_without_stored_row_still_found(self, session, seed_source):
        _seed_corpus(session, seed_source)
        emb.backfill_embeddings(session.connection())
        stray = _article(
            session, seed_source, "https://example.com/stray", text="straggler ransomware report"
        )
        hits = semantic_search(session, "straggler ransomware", limit=10)
        assert stray.id in [h.object_id for h in hits]


class TestInvalidation:
    def test_sync_reembeds_only_on_change(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/i1", text="alpha bravo")
        assert emb.sync_article_embeddings(session, [art.id]) == 1
        session.commit()
        first_hash = session.get(ArticleEmbedding, art.id).content_hash
        # No change → no re-embed.
        assert emb.sync_article_embeddings(session, [art.id]) == 0
        # Change → re-embed, new hash, new ranking behavior.
        art.extracted_text = "charlie delta echo"
        session.commit()
        assert emb.sync_article_embeddings(session, [art.id]) == 1
        session.commit()
        row = session.get(ArticleEmbedding, art.id)
        assert row.content_hash != first_hash
        assert [h.object_id for h in semantic_search(session, "charlie delta", limit=1)] == [art.id]

    def test_never_raises_on_bad_input(self, session):
        assert emb.sync_article_embeddings(session, []) == 0
        assert emb.sync_article_embeddings(session, [999999]) == 0  # unknown id


class TestPacking:
    def test_pack_unpack_roundtrip(self):
        vec = embed("roundtrip tokens here")
        blob = emb.pack(vec)
        assert len(blob) == 4 * emb.VECTOR_DIM
        back = emb.unpack(blob)
        assert len(back) == emb.VECTOR_DIM
        assert all(abs(a - b) < 1e-6 for a, b in zip(back, vec, strict=True))

    def test_score_skips_wrong_sized_blobs(self):
        from scry.search.semantic import _score_stored

        good = emb.pack(embed("good vector"))
        scored = _score_stored(embed("good vector"), [(1, good), (2, b"short")])
        assert [rid for _, rid in scored] == [1]


# ------------------------- write-path hooks -------------------------


def _rss(links: list[str]) -> str:
    published = format_datetime(datetime.now(UTC) - timedelta(hours=1))
    items = "".join(
        f"<item><title>item-{i}</title><link>{link}</link><pubDate>{published}</pubDate>"
        f"<description>quokkavector campaign report</description></item>"
        for i, link in enumerate(links)
    )
    return (
        '<?xml version="1.0"?>\n<rss version="2.0"><channel>'
        "<title>t</title><link>https://example.com/</link><description>d</description>"
        + items
        + "</channel></rss>"
    )


def _patch_fetcher(monkeypatch, text: str) -> None:
    result = FetchResult(
        url="https://example.com/blog/feed",
        status_code=200,
        content=text.encode(),
        text=text,
        headers={"content-type": "application/rss+xml"},
        content_hash="abc",
    )

    class _FakeFetcher:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def fetch(self, url, **kwargs):
            return result

    monkeypatch.setattr(ingest_engine_module, "SafeFetcher", _FakeFetcher)


class TestWriteHooks:
    async def test_feed_ingest_embeds_articles(self, session, seed_source, monkeypatch):
        _patch_fetcher(monkeypatch, _rss(["https://example.com/v1", "https://example.com/v2"]))
        res = await IngestionEngine(session).ingest_source(seed_source)
        assert res["articles"] == 2
        rows = session.scalars(select(ArticleEmbedding)).all()
        assert len(rows) == 2
        hits = semantic_search(session, "quokkavector campaign", limit=5)
        assert len(hits) == 2

    def test_pipeline_processing_embeds_article(self, session, seed_source, fixture_dir):
        art = _article(
            session,
            seed_source,
            "https://example.com/p1",
            text=(fixture_dir / "ransomware.txt").read_text(),
        )
        CTIPipeline(session).process_article(art)
        row = session.get(ArticleEmbedding, art.id)
        assert row is not None
        assert row.dim == emb.VECTOR_DIM
        first_hash = row.content_hash
        # Reprocess with unchanged text → hash unchanged (no re-embed).
        CTIPipeline(session).process_article(art)
        assert session.get(ArticleEmbedding, art.id).content_hash == first_hash
