"""raw_html retention pruning tests (v0.14.0).

Prune-by-age correctness, dry-run, disabled semantics, CLI flags, scheduler
wiring, refetch-on-demand after a prune, and NULL-safe readers.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import scry.ingestion.ingest_engine as ingest_engine_module
import scry.scheduler as sched_mod
from scry.cli import app as cli_app
from scry.config import get_settings
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.models import Article, ArticleEmbedding
from scry.retention import human_bytes, prune_raw_html, vacuum_sqlite
from scry.search.embeddings import sync_article_embeddings
from scry.search.semantic import semantic_search

runner = CliRunner()
NOW = datetime.now(UTC)


def _article(
    session,
    source,
    url: str,
    *,
    age_days: int | None = 60,
    raw: str | None = "<html><body>full page</body></html>",
    text: str = "ransomware body " * 100,
    published_age_days: int | None = None,
) -> Article:
    art = Article(
        source_id=source.id,
        title="t",
        url=url,
        ingested_at=(NOW - timedelta(days=age_days)) if age_days is not None else None,
        published_at=(NOW - timedelta(days=published_age_days)) if published_age_days is not None else None,
        extracted_text=text,
        raw_html=raw,
    )
    session.add(art)
    session.commit()
    return art


def _fresh(session, article_id: int) -> Article:
    session.expire_all()
    return session.get(Article, article_id)


# ------------------------- core prune -------------------------


class TestPrune:
    def test_old_pruned_recent_kept(self, session, seed_source):
        old = _article(session, seed_source, "https://example.com/old", age_days=60)
        recent = _article(session, seed_source, "https://example.com/new", age_days=5)

        res = prune_raw_html(session, 30)

        assert res["candidates"] == 1 and res["pruned"] == 1
        assert _fresh(session, old.id).raw_html is None
        assert _fresh(session, recent.id).raw_html is not None

    def test_row_text_and_derived_data_preserved(self, session, seed_source):
        old = _article(session, seed_source, "https://example.com/old", age_days=90)
        sync_article_embeddings(session, [old.id])
        session.commit()
        assert session.scalars(select(ArticleEmbedding)).one().article_id == old.id

        prune_raw_html(session, 30)

        kept = _fresh(session, old.id)
        assert kept is not None  # row kept
        assert kept.extracted_text == "ransomware body " * 100  # searchable text kept
        assert kept.raw_html is None
        # derived embedding row untouched (it never embeds raw_html)…
        assert session.scalars(select(ArticleEmbedding)).all()
        # …and semantic search still finds the pruned article
        hits = semantic_search(session, "ransomware", target="articles", limit=5)
        assert [h.object_id for h in hits] == [old.id]

    def test_age_falls_back_to_published_at(self, session, seed_source):
        # No ingested_at: published_at anchors the age.
        art = _article(session, seed_source, "https://example.com/pub", age_days=None, published_age_days=45)
        prune_raw_html(session, 30)
        assert _fresh(session, art.id).raw_html is None

    def test_no_age_signal_never_pruned(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/ageless", age_days=None)
        res = prune_raw_html(session, 30)
        assert res["candidates"] == 0
        assert _fresh(session, art.id).raw_html is not None

    def test_already_pruned_not_recounted(self, session, seed_source):
        _article(session, seed_source, "https://example.com/gone", age_days=60, raw=None)
        res = prune_raw_html(session, 30)
        assert res["candidates"] == 0 and res["pruned"] == 0

    def test_bytes_estimate_matches_html_length(self, session, seed_source):
        raw = "<html>" + "x" * 10_000 + "</html>"
        _article(session, seed_source, "https://example.com/sized", age_days=60, raw=raw)
        res = prune_raw_html(session, 30, dry_run=True)
        assert res["bytes_reclaimed"] == len(raw)

    def test_dry_run_writes_nothing(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/dry", age_days=60)
        res = prune_raw_html(session, 30, dry_run=True)
        assert res["candidates"] == 1 and res["pruned"] == 0
        assert _fresh(session, art.id).raw_html is not None

    @pytest.mark.parametrize("days", [0, -5])
    def test_disabled(self, session, seed_source, days):
        art = _article(session, seed_source, f"https://example.com/off{days}", age_days=999)
        res = prune_raw_html(session, days)
        assert res["enabled"] is False and res["pruned"] == 0
        assert _fresh(session, art.id).raw_html is not None


# ------------------------- CLI -------------------------


class TestCLI:
    def test_dry_run_flag(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/c1", age_days=60)
        r = runner.invoke(cli_app, ["prune-html", "--days", "1", "--dry-run"])
        assert r.exit_code == 0, r.output
        assert "DRY RUN" in r.output and "Would prune" in r.output
        assert _fresh(session, art.id).raw_html is not None

    def test_real_run_prunes_and_vacuums(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/c2", age_days=60)
        r = runner.invoke(cli_app, ["prune-html", "--days", "1"])
        assert r.exit_code == 0, r.output
        assert "Pruned" in r.output and "1" in r.output
        assert "VACUUM done" in r.output
        assert _fresh(session, art.id).raw_html is None

    def test_no_vacuum_flag(self, session, seed_source):
        _article(session, seed_source, "https://example.com/c3", age_days=60)
        r = runner.invoke(cli_app, ["prune-html", "--days", "1", "--no-vacuum"])
        assert r.exit_code == 0, r.output
        assert "VACUUM" not in r.output

    def test_disabled_message(self, session, seed_source):
        art = _article(session, seed_source, "https://example.com/c4", age_days=60)
        r = runner.invoke(cli_app, ["prune-html", "--days", "0"])
        assert r.exit_code == 0, r.output
        assert "disabled" in r.output
        assert _fresh(session, art.id).raw_html is not None

    def test_default_days_comes_from_setting(self, session, seed_source, monkeypatch):
        monkeypatch.setenv("CTI_RAW_HTML_RETENTION_DAYS", "10")
        get_settings.cache_clear()
        old = _article(session, seed_source, "https://example.com/c5", age_days=60)
        recent = _article(session, seed_source, "https://example.com/c6", age_days=3)
        r = runner.invoke(cli_app, ["prune-html", "--no-vacuum"])
        assert r.exit_code == 0, r.output
        assert _fresh(session, old.id).raw_html is None
        assert _fresh(session, recent.id).raw_html is not None


# ------------------------- refetch on demand -------------------------


def _patch_fetcher(monkeypatch, text: str) -> None:
    result = FetchResult(
        url="https://example.com/article",
        status_code=200,
        content=text.encode(),
        text=text,
        headers={"content-type": "text/html"},
        content_hash="abc",
    )

    class _FakeFetcher:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def fetch(self, url, *, policy=None, rate_limit_per_minute=10):
            return result

    monkeypatch.setattr(ingest_engine_module, "SafeFetcher", _FakeFetcher)


class TestRefetch:
    async def test_fetch_full_content_recovers_pruned_article(self, session, seed_source, monkeypatch):
        # A pruned stub: no raw_html, short extracted_text → fetch candidate.
        art = _article(
            session,
            seed_source,
            "https://example.com/pruned",
            age_days=60,
            raw=None,
            text="short stub",
        )
        page = "<html><body><article><p>" + "full story " * 200 + "</p></article></body></html>"
        _patch_fetcher(monkeypatch, page)

        res = await IngestionEngine(session).fetch_full_content()

        assert res["updated"] == 1, res
        recovered = _fresh(session, art.id)
        assert recovered.raw_html is not None  # re-fetched from URL
        assert len(recovered.extracted_text) > len("short stub")
        assert recovered.extractor_version == "0"  # queued for re-extraction


# ------------------------- NULL-safe readers -------------------------


class TestNullReaders:
    def test_article_detail_page_renders_without_raw_html(self, session, seed_source):
        from fastapi.testclient import TestClient

        from scry.main import app

        art = _article(session, seed_source, "https://example.com/ui", age_days=5, raw=None)
        client = TestClient(app)
        r = client.get(f"/ui/articles/{art.id}")
        assert r.status_code == 200, r.text[:500]

    def test_vacuum_sqlite_runs_on_sqlite(self, session):
        from scry.db import get_engine

        assert vacuum_sqlite(get_engine()) is True


# ------------------------- scheduler wiring -------------------------


class TestSchedulerJob:
    def test_job_registered_weekly_off_peak(self):
        sched = sched_mod._build_scheduler(get_settings())
        job = sched.get_job("raw_html_prune")
        assert job is not None
        fields = {f.name: str(f) for f in job.trigger.fields}
        assert fields["day_of_week"] == "sun"
        assert fields["hour"] == "4"
        assert fields["minute"] == "47"

    def test_job_skips_when_disabled(self, session, seed_source, monkeypatch):
        monkeypatch.setenv("CTI_RAW_HTML_RETENTION_DAYS", "0")
        get_settings.cache_clear()
        art = _article(session, seed_source, "https://example.com/s1", age_days=999)
        sched_mod._prune_raw_html_job()  # must not raise
        assert _fresh(session, art.id).raw_html is not None

    def test_job_prunes_when_enabled(self, session, seed_source, monkeypatch):
        monkeypatch.setenv("CTI_RAW_HTML_RETENTION_DAYS", "30")
        get_settings.cache_clear()
        art = _article(session, seed_source, "https://example.com/s2", age_days=60)
        sched_mod._prune_raw_html_job()
        assert _fresh(session, art.id).raw_html is None


# ------------------------- helpers -------------------------


def test_human_bytes():
    assert human_bytes(0) == "0 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048) == "2.0 KB"
    assert human_bytes(5 * 1024 * 1024) == "5.0 MB"
