"""FTS5 full-text search tests.

The conftest DB fixture only runs create_all, so FTS tables don't exist
unless a test applies the migration (``fts_db`` fixture) — which also means
the whole pre-existing search test-suite exercises the LIKE fallback.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import pytest
from sqlalchemy import select

import scry.ingestion.ingest_engine as ingest_engine_module
import scry.search.fts as fts_mod
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.migrations import run_migrations
from scry.models import Article, Claim, Entity, Observable
from scry.pipeline import CTIPipeline
from scry.search import full_text_search
from scry.search.full_text import sanitize_fts_query


@pytest.fixture(autouse=True)
def _clear_fts_memo():
    """Engine ids are reused across tests — never leak the readiness memo."""
    fts_mod._READY.clear()
    yield
    fts_mod._READY.clear()


@pytest.fixture
def fts_db(session):
    """Session with the FTS5 migration applied (tables created + backfilled)."""
    run_migrations()
    fts_mod.fts_invalidate(session)
    return session


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


def _fts_count(session, fts_table: str) -> int:
    return session.connection().exec_driver_sql(f"SELECT count(*) FROM {fts_table}").scalar() or 0


# ------------------------- detection & migration -------------------------


class TestAvailability:
    def test_fts5_supported_on_sqlite(self, session):
        assert fts_mod.fts5_supported(session.connection()) is True

    def test_tables_created_and_backfilled_idempotently(self, session, seed_source):
        _article(session, seed_source, "https://example.com/f1", text="lockbit ransomware")
        ob = Observable(type="domain", value="evil.example", normalized_value="evil.example")
        session.add(ob)
        session.commit()

        run_migrations()
        for table in ("articles_fts", "observables_fts", "entities_fts", "claims_fts"):
            assert (
                session.connection()
                .exec_driver_sql("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,))
                .scalar()
            )
        assert _fts_count(session, "articles_fts") == 1
        assert _fts_count(session, "observables_fts") == 1

        run_migrations()  # second pass: no duplicates, no errors
        assert _fts_count(session, "articles_fts") == 1
        assert _fts_count(session, "observables_fts") == 1

    def test_ready_memo_and_invalidate(self, fts_db):
        assert fts_mod.fts_ready(fts_db) is True
        fts_mod.fts_invalidate(fts_db)
        assert fts_mod.fts_ready(fts_db) is True  # re-detected

    def test_not_ready_without_tables(self, session):
        assert fts_mod.fts_ready(session) is False


# ------------------------- query sanitizer -------------------------


class TestSanitizer:
    def test_plain_tokens_and_combined(self):
        assert sanitize_fts_query("lockbit ransomware") == '"lockbit" AND "ransomware"'

    def test_operators_become_literals(self):
        assert sanitize_fts_query("CVE-2024-3400 OR") == '"CVE-2024-3400" AND "OR"'
        assert sanitize_fts_query('"unterminated') == '"unterminated"'
        assert sanitize_fts_query("NEAR(") == '"NEAR"'

    def test_punctuation_only_returns_none(self):
        assert sanitize_fts_query("!!! ***") is None
        assert sanitize_fts_query("  ") is None


# ------------------------- MATCH correctness & ranking -------------------------


class TestFtsSearch:
    def test_article_hit_and_shape(self, fts_db, seed_source):
        art = _article(
            fts_db,
            seed_source,
            "https://example.com/a1",
            title="LockBit hits hospitals",
            text="LockBit affiliates breached three US hospitals.",
        )
        run_migrations()
        hits = full_text_search(fts_db, "lockbit", limit=10)
        assert hits
        hit = next(h for h in hits if h.object_type == "article")
        assert hit.object_id == art.id
        assert hit.title == "LockBit hits hospitals"
        assert hit.snippet
        assert hit.score > 0

    def test_ranking_prefers_stronger_match(self, fts_db, seed_source):
        weak = _article(
            fts_db,
            seed_source,
            "https://example.com/weak",
            text="phobos appeared once. " + "filler words everywhere. " * 20,
        )
        strong = _article(
            fts_db,
            seed_source,
            "https://example.com/strong",
            text="phobos phobos phobos phobos phobos",
        )
        run_migrations()
        hits = [h for h in full_text_search(fts_db, "phobos", limit=10) if h.object_type == "article"]
        assert {h.object_id for h in hits} == {weak.id, strong.id}
        assert hits[0].object_id == strong.id  # higher term frequency ranks first
        assert hits[0].score > hits[1].score

    def test_observable_entity_claim_hits(self, fts_db, seed_source):
        ob = Observable(type="ipv4", value="185.220.101.47", normalized_value="185.220.101.47")
        ent = Entity(type="threat_actor", canonical_name="APT29", aliases=["Cozy Bear", "NOBELIUM"])
        art = _article(fts_db, seed_source, "https://example.com/c1", text="t")
        claim = Claim(
            article_id=art.id,
            claim_type="attribution",
            claim_text="Acme breach attributed to Fancy Zebra collective",
            evidence_text="Researchers described the Fancy Zebra intrusion set",
        )
        fts_db.add_all([ob, ent, claim])
        fts_db.commit()
        run_migrations()

        hits = full_text_search(fts_db, "185.220.101.47", limit=10)
        assert any(h.object_type == "observable" and h.object_id == ob.id for h in hits)

        # Aliases are indexed — the LIKE path only ever searched canonical_name.
        hits = full_text_search(fts_db, "Cozy Bear", limit=10)
        assert any(h.object_type == "entity" and h.object_id == ent.id for h in hits)

        hits = full_text_search(fts_db, "Fancy Zebra", limit=10)
        assert any(h.object_type == "claim" and h.object_id == claim.id for h in hits)

    def test_snippet_centers_on_match_beyond_300_chars(self, fts_db, seed_source):
        tail = "the intruders deployed zebracorn implants across the estate"
        _article(
            fts_db,
            seed_source,
            "https://example.com/long",
            text=("padding sentence number one. " * 40) + tail,
        )
        run_migrations()
        hits = full_text_search(fts_db, "zebracorn", limit=5)
        assert hits
        # snippet() excerpts around the match; the old [:300] slice would miss it
        assert "zebracorn" in hits[0].snippet

    def test_types_filter_respected(self, fts_db, seed_source):
        _article(fts_db, seed_source, "https://example.com/t1", text="lockbit ransomware")
        run_migrations()
        hits = full_text_search(fts_db, "lockbit", limit=10, types=["observable"])
        assert hits == []


class TestSpecialCharacters:
    @pytest.mark.parametrize(
        "query",
        [
            "CVE-2024-3400 OR",
            '"unterminated',
            "*",
            "(AND)",
            "NEAR(",
            '"""',
            "lockbit OR NOT ransomware",
            "title:lockbit",
            "-",
            "!!!",
        ],
    )
    def test_operator_queries_never_raise(self, fts_db, seed_source, query):
        _article(fts_db, seed_source, "https://example.com/op", text="lockbit ransomware note")
        run_migrations()
        hits = full_text_search(fts_db, query, limit=10)  # must not raise
        assert isinstance(hits, list)


class TestFallback:
    def test_broken_index_falls_back_to_like(self, fts_db, seed_source):
        art = _article(fts_db, seed_source, "https://example.com/fb", text="lockbit hospitals")
        run_migrations()
        assert fts_mod.fts_ready(fts_db) is True

        # Break the index mid-process: the memo still says ready, the MATCH
        # fails, and the LIKE scan must take over (and the memo resets).
        fts_db.connection().exec_driver_sql("DROP TABLE articles_fts")
        hits = full_text_search(fts_db, "lockbit", limit=10)
        assert any(h.object_type == "article" and h.object_id == art.id for h in hits)
        assert fts_mod.fts_ready(fts_db) is False

        # And stays on LIKE without further errors.
        hits = full_text_search(fts_db, "lockbit", limit=10)
        assert any(h.object_id == art.id for h in hits)


# ------------------------- incremental index maintenance -------------------------


def _rss(links: list[str]) -> str:
    published = format_datetime(datetime.now(UTC) - timedelta(hours=1))
    items = "".join(
        f"<item><title>item-{i}</title><link>{link}</link><pubDate>{published}</pubDate>"
        f"<description>report about quokkagrass campaign</description></item>"
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


def _match_rowids(session, fts_table: str, term: str) -> set[int]:
    return {
        r[0]
        for r in session.connection()
        .exec_driver_sql(f"SELECT rowid FROM {fts_table} WHERE {fts_table} MATCH ?", (f'"{term}"',))
        .all()
    }


class TestIncrementalIndexing:
    async def test_new_feed_articles_indexed_without_rebuild(self, fts_db, seed_source, monkeypatch):
        run_migrations()
        _patch_fetcher(monkeypatch, _rss(["https://example.com/n1", "https://example.com/n2"]))
        res = await IngestionEngine(fts_db).ingest_source(seed_source)
        assert res["articles"] == 2
        # Searchable immediately — no migration/rebuild in between.
        hits = full_text_search(fts_db, "quokkagrass", limit=10)
        assert len([h for h in hits if h.object_type == "article"]) == 2

    def test_pipeline_indexes_and_reprocess_stays_clean(self, fts_db, seed_source, fixture_dir):
        art = _article(
            fts_db,
            seed_source,
            "https://example.com/p1",
            text=(fixture_dir / "ransomware.txt").read_text(),
        )
        run_migrations()
        pipeline = CTIPipeline(fts_db)
        pipeline.process_article(art)

        obs_ids = _match_rowids(fts_db, "observables_fts", "bad-cdn")
        assert obs_ids
        ent_ids = _match_rowids(fts_db, "entities_fts", "LockBit")
        assert ent_ids
        claim_count = len(fts_db.scalars(select(Claim).where(Claim.article_id == art.id)).all())
        assert claim_count > 0
        assert _fts_count(fts_db, "claims_fts") == claim_count

        # Reprocess: claims are deleted + recreated; the FTS table must not
        # keep orphaned entries for the old claim ids.
        pipeline.process_article(art)
        new_claim_count = len(fts_db.scalars(select(Claim).where(Claim.article_id == art.id)).all())
        assert new_claim_count == claim_count > 0
        assert _fts_count(fts_db, "claims_fts") == new_claim_count

    def test_article_update_replaces_index_tokens(self, fts_db, seed_source):
        art = _article(fts_db, seed_source, "https://example.com/u1", text="first wording")
        run_migrations()
        assert _match_rowids(fts_db, "articles_fts", "wording") == {art.id}

        art.extracted_text = "completely different secondtext"
        fts_db.commit()
        fts_mod.index_rows(fts_db, "article", [art.id])
        fts_db.commit()

        assert _match_rowids(fts_db, "articles_fts", "wording") == set()  # stale token gone
        assert _match_rowids(fts_db, "articles_fts", "secondtext") == {art.id}


class TestRebuild:
    def test_rebuild_fts_repopulates(self, fts_db, seed_source):
        _article(fts_db, seed_source, "https://example.com/r1", text="lockbit rebuild check")
        run_migrations()
        fts_db.connection().exec_driver_sql("DELETE FROM articles_fts")
        assert _match_rowids(fts_db, "articles_fts", "lockbit") == set()

        counts = fts_mod.rebuild_fts(fts_db)
        fts_db.commit()
        assert counts["article"] >= 1
        assert _match_rowids(fts_db, "articles_fts", "lockbit")


class TestAiRetrieval:
    def test_collect_sources_uses_fts_without_changes(self, fts_db, seed_source):
        """scry.api.ai._collect_sources calls full_text_search per keyword —
        it benefits from FTS5 with zero modifications."""
        import scry.api.ai as ai_mod

        _article(
            fts_db,
            seed_source,
            "https://example.com/ai1",
            title="LockBit ransomware hits hospitals",
            text="LockBit affiliates breached three US hospitals using phishing.",
        )
        run_migrations()
        sources = ai_mod._collect_sources(fts_db, "lockbit hospitals phishing", limit=8)
        assert sources
        assert sources[0]["title"] == "LockBit ransomware hits hospitals"
