"""Scheduled full-content fetch.

RSS-stub articles (short summary, no stored HTML) get their full page fetched
after each scheduled ingest, bounded per run, with an age window, a back-off
for failing URLs, and no endless refetching of pages that are simply short.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

from sqlalchemy import select

import scry.ingestion.ingest_engine as ingest_engine_module
import scry.scheduler as sched_mod
from scry.config import get_settings
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.models import Article, Observable, Source, SourceFetch
from scry.search import full_text_search

NOW = datetime.now(UTC)
PARA = (
    "Researchers observed the Lumma stealer contacting the command-and-control server "
    "evil-c2.example.net during a phishing campaign. "
)
LONG_PAGE = (
    "<html><head><title>Full story</title></head><body><article><h1>Full story</h1>"
    + "".join(
        f"<p>Observation {i}: {PARA}Sample {i * 7919} was reported by vendor {i}.</p>" for i in range(8)
    )
    + "</article></body></html>"
)
SHORT_PAGE = (
    "<html><head><title>Stormcast</title></head><body><article><h1>Stormcast</h1>"
    "<p>Handler on duty: someone. Threat level: green.</p></article>"
    "<!-- " + "padding " * 80 + "--></body></html>"
)
EMPTY_PAGE = "<html><body><script>var x=1;</script><!-- " + "padding " * 80 + "--></body></html>"


class FakeFetcher:
    """Patched in for SafeFetcher; records every URL fetched."""

    calls: ClassVar[list[str]] = []
    responses: ClassVar[dict[str, FetchResult]] = {}
    default: ClassVar[FetchResult | None] = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def fetch(self, url, *, policy=None, rate_limit_per_minute=10):
        type(self).calls.append(url)
        res = type(self).responses.get(url) or type(self).default
        assert res is not None, f"unexpected fetch of {url}"
        return res


def _ok(body: str, url: str = "u") -> FetchResult:
    return FetchResult(
        url=url, status_code=200, content=body.encode(), text=body, headers={"content-type": "text/html"}
    )


def _err(error: str = "HTTP 503 after 3 attempts", status: int | None = 503) -> FetchResult:
    return FetchResult(url="u", status_code=status, error=error)


def _patch(monkeypatch, *, default: FetchResult | None = None, responses=None):
    FakeFetcher.calls = []
    FakeFetcher.responses = responses or {}
    FakeFetcher.default = default
    monkeypatch.setattr(ingest_engine_module, "SafeFetcher", FakeFetcher)
    return FakeFetcher


def _stub(session, source, url, *, age_hours: float = 1, text: str = "short summary", raw=None) -> Article:
    art = Article(
        source_id=source.id,
        title=f"stub {url[-6:]}",
        url=url,
        ingested_at=NOW - timedelta(hours=age_hours),
        extracted_text=text,
        raw_html=raw,
        extractor_version="0.1",
    )
    session.add(art)
    session.commit()
    return art


def _fresh(session, art_id: int) -> Article:
    session.expire_all()
    return session.get(Article, art_id)


class TestSelectionAndUpdate:
    async def test_stub_gets_full_text_and_is_queued_for_extraction(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        art = _stub(session, seed_source, "https://example.com/a1")
        res = await IngestionEngine(session).fetch_full_content()
        assert res == {"updated": 1, "unchanged": 0, "failed": 0, "skipped": 0}
        got = _fresh(session, art.id)
        assert "evil-c2.example.net" in got.extracted_text and len(got.extracted_text) > 1000
        assert got.raw_html == LONG_PAGE
        assert got.extractor_version == "0"
        assert fetcher.calls == ["https://example.com/a1"]
        hits = full_text_search(session, "Lumma", limit=5)
        assert art.id in {h.object_id for h in hits if h.object_type == "article"}

    async def test_articles_with_html_or_long_text_are_not_candidates(
        self, session, seed_source, monkeypatch
    ):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        _stub(session, seed_source, "https://example.com/has-html", raw="<html>stored</html>")
        _stub(session, seed_source, "https://example.com/long-text", text="x" * 1500)
        res = await IngestionEngine(session).fetch_full_content()
        assert res["updated"] == 0 and fetcher.calls == []

    async def test_max_age_excludes_old_articles(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        _stub(session, seed_source, "https://example.com/old", age_hours=24 * 10)
        _stub(session, seed_source, "https://example.com/new", age_hours=2)
        res = await IngestionEngine(session).fetch_full_content(max_age_hours=72)
        assert res["updated"] == 1 and fetcher.calls == ["https://example.com/new"]
        # Unbounded (manual endpoint behaviour) still reaches the old one.
        res = await IngestionEngine(session).fetch_full_content()
        assert fetcher.calls[-1] == "https://example.com/old"

    async def test_disabled_source_is_excluded_and_does_not_consume_the_limit(
        self, session, seed_source, monkeypatch
    ):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        off = Source(
            name="Off",
            type="news",
            url="https://off.example.com",
            enabled=False,
            baseline_confidence=60,
            collection_policy="safe_public_web",
        )
        session.add(off)
        session.commit()
        _stub(session, seed_source, "https://example.com/enabled-older")
        _stub(session, off, "https://off.example.com/newer-but-disabled")  # higher id
        res = await IngestionEngine(session).fetch_full_content(limit=1)
        assert res["updated"] == 1
        assert fetcher.calls == ["https://example.com/enabled-older"]


class TestBackoffAndCompletion:
    async def test_failure_is_recorded_and_backs_off(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_err())
        art = _stub(session, seed_source, "https://example.com/flaky")
        engine = IngestionEngine(session)

        res = await engine.fetch_full_content(retry_after_hours=6)
        assert res["failed"] == 1 and res["updated"] == 0
        row = session.scalars(select(SourceFetch).where(SourceFetch.url == art.url)).one()
        assert row.error and row.status_code == 503 and row.source_id == seed_source.id

        res = await engine.fetch_full_content(retry_after_hours=6)  # within back-off window
        assert res == {"updated": 0, "unchanged": 0, "failed": 0, "skipped": 0}
        assert fetcher.calls == [art.url]  # not fetched again

        res = await engine.fetch_full_content()  # manual path: no back-off
        assert fetcher.calls == [art.url, art.url] and res["failed"] == 1

    async def test_failure_older_than_the_window_is_retried(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        art = _stub(session, seed_source, "https://example.com/retry-later")
        session.add(
            SourceFetch(
                source_id=seed_source.id,
                fetched_at=NOW - timedelta(hours=7),
                status_code=503,
                url=art.url,
                error="old failure",
            )
        )
        session.commit()
        res = await IngestionEngine(session).fetch_full_content(retry_after_hours=6)
        assert res["updated"] == 1 and fetcher.calls == [art.url]

    async def test_short_body_counts_as_failure(self, session, seed_source, monkeypatch):
        _patch(monkeypatch, default=_ok("<html>tiny</html>"))
        art = _stub(session, seed_source, "https://example.com/tiny")
        res = await IngestionEngine(session).fetch_full_content(retry_after_hours=6)
        assert res["failed"] == 1
        err = session.scalars(select(SourceFetch).where(SourceFetch.url == art.url)).one().error
        assert "too short" in err

    async def test_short_but_successful_page_is_not_refetched_forever(
        self, session, seed_source, monkeypatch
    ):
        fetcher = _patch(monkeypatch, default=_ok(SHORT_PAGE))
        art = _stub(session, seed_source, "https://example.com/stormcast", text="x" * 900)
        engine = IngestionEngine(session)
        res = await engine.fetch_full_content()
        assert res["unchanged"] == 1 and res["updated"] == 0
        got = _fresh(session, art.id)
        assert got.extracted_text == "x" * 900  # nothing longer to store
        assert got.raw_html == SHORT_PAGE and got.extractor_version == "0.1"
        await engine.fetch_full_content()
        assert fetcher.calls == [art.url]  # second run: no longer a candidate

    async def test_unparseable_page_never_stores_raw_html_as_text(self, session, seed_source, monkeypatch):
        _patch(monkeypatch, default=_ok(EMPTY_PAGE))
        art = _stub(session, seed_source, "https://example.com/empty", text="summary")
        res = await IngestionEngine(session).fetch_full_content()
        assert res["unchanged"] == 1
        got = _fresh(session, art.id)
        assert got.extracted_text == "summary" and "<script>" not in got.extracted_text

    async def test_limit_bounds_the_run(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        for i in range(5):
            _stub(session, seed_source, f"https://example.com/n{i}")
        res = await IngestionEngine(session).fetch_full_content(limit=2)
        assert res["updated"] == 2 and len(fetcher.calls) == 2


class TestSchedulerWiring:
    def _no_feeds(self, monkeypatch):
        async def _noop(self):
            return {}

        monkeypatch.setattr(IngestionEngine, "ingest_all", _noop)

    def test_job_fetches_then_extracts_in_the_same_run(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        self._no_feeds(monkeypatch)
        art = _stub(session, seed_source, "https://example.com/sched")
        sched_mod._ingest_all_job()
        got = _fresh(session, art.id)
        assert fetcher.calls == [art.url]
        assert got.extractor_version != "0"  # the pipeline processed the upgraded article
        assert session.scalar(select(Observable).where(Observable.normalized_value == "evil-c2.example.net"))

    def test_job_respects_the_disable_switch(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        self._no_feeds(monkeypatch)
        monkeypatch.setenv("CTI_FULL_FETCH_ENABLED", "false")
        get_settings.cache_clear()
        art = _stub(session, seed_source, "https://example.com/off")
        sched_mod._ingest_all_job()
        assert fetcher.calls == [] and _fresh(session, art.id).raw_html is None

    def test_job_applies_limit_and_age_settings(self, session, seed_source, monkeypatch):
        fetcher = _patch(monkeypatch, default=_ok(LONG_PAGE))
        self._no_feeds(monkeypatch)
        monkeypatch.setenv("CTI_FULL_FETCH_LIMIT", "1")
        monkeypatch.setenv("CTI_FULL_FETCH_MAX_AGE_HOURS", "24")
        get_settings.cache_clear()
        _stub(session, seed_source, "https://example.com/too-old", age_hours=100)
        _stub(session, seed_source, "https://example.com/a", age_hours=3)
        _stub(session, seed_source, "https://example.com/b", age_hours=2)
        sched_mod._ingest_all_job()
        assert len(fetcher.calls) == 1 and "too-old" not in fetcher.calls[0]

    def test_a_fetch_failure_never_blocks_extraction(self, session, seed_source, monkeypatch):
        _patch(monkeypatch, default=_ok(LONG_PAGE))
        self._no_feeds(monkeypatch)

        async def _boom(self, *a, **k):
            raise RuntimeError("network exploded")

        monkeypatch.setattr(IngestionEngine, "fetch_full_content", _boom)
        pending = Article(
            source_id=seed_source.id,
            title="pending",
            url="https://example.com/pending",
            ingested_at=NOW,
            extracted_text="APT29 uses Cobalt Strike with c2-9.example.net for persistence.",
        )
        session.add(pending)
        session.commit()
        sched_mod._ingest_all_job()  # must not raise
        assert _fresh(session, pending.id).extractor_version != "0"
