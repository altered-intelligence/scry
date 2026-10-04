"""Single-URL ingest must parse the page.

``IngestionEngine._persist_fetch`` used to store ad-hoc ingests (``POST
/ingest/url``, ``scry ingest-url``, a source whose URL is one page) with an
empty title and empty text; nothing re-parsed them, so extraction found
nothing. Also covers feeds that were mistaken for article pages when served
without an XML content-type or declaration.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

import scry.ingestion.ingest_engine as ingest_engine_module
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.ingestion.rss import looks_like_feed
from scry.main import app
from scry.models import Article, Observable, Source
from scry.pipeline import CTIPipeline
from scry.search import full_text_search

PAGE_URL = "https://example.com/blog/lumma-campaign"
PARAGRAPH = (
    "Researchers observed the Lumma stealer contacting the command-and-control server "
    "evil-c2.example.net during a phishing campaign. "
)
PAGE = (
    "<html lang='en'><head><title>Lumma campaign analysis</title>"
    "<meta name='author' content='Jane Analyst'>"
    f"<link rel='canonical' href='{PAGE_URL}'></head><body><nav>menu</nav>"
    "<article><h1>Lumma campaign analysis</h1>"
    + "".join(f"<p>{PARAGRAPH}</p>" for _ in range(8))
    + "</article>"
    "<footer>copyright</footer></body></html>"
)
RSS = (
    "<rss version='2.0'><channel><title>Feed</title>"
    "<item><title>Post one</title><link>https://example.com/p1</link><description>one</description></item>"
    "<item><title>Post two</title><link>https://example.com/p2</link><description>two</description></item>"
    "</channel></rss>"
)


def _patch_fetcher(monkeypatch, body: str, *, url: str = PAGE_URL, content_type: str = "text/html"):
    result = FetchResult(
        url=url,
        status_code=200,
        content=body.encode(),
        text=body,
        headers={"content-type": content_type},
        content_hash="abc123",
    )

    class _FakeFetcher:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def fetch(self, url, *, policy=None, rate_limit_per_minute=10):
            return result

    monkeypatch.setattr(ingest_engine_module, "SafeFetcher", _FakeFetcher)


class TestPageIsParsed:
    async def test_ingest_url_extracts_title_text_and_metadata(self, session, seed_source, monkeypatch):
        _patch_fetcher(monkeypatch, PAGE)
        art = await IngestionEngine(session).ingest_url(PAGE_URL, source_id=seed_source.id)
        assert art is not None
        assert art.title == "Lumma campaign analysis"
        assert "evil-c2.example.net" in art.extracted_text
        assert "menu" not in art.extracted_text and "copyright" not in art.extracted_text
        assert art.raw_html == PAGE  # kept for re-parsing, like feed articles
        assert art.canonical_url == PAGE_URL
        assert art.extractor_version == "0"  # queued for the extraction pipeline

    async def test_page_is_searchable_straight_after_ingest(self, session, seed_source, monkeypatch):
        _patch_fetcher(monkeypatch, PAGE)
        art = await IngestionEngine(session).ingest_url(PAGE_URL, source_id=seed_source.id)
        hits = full_text_search(session, "Lumma", limit=10)
        assert art.id in {h.object_id for h in hits if h.object_type == "article"}

    async def test_pipeline_now_extracts_iocs_from_the_page(self, session, seed_source, monkeypatch):
        _patch_fetcher(monkeypatch, PAGE)
        art = await IngestionEngine(session).ingest_url(PAGE_URL, source_id=seed_source.id)
        CTIPipeline(session).process_article(art)
        values = {o.normalized_value for o in session.scalars(select(Observable)).all()}
        assert "evil-c2.example.net" in values

    async def test_endpoint_ingest_returns_a_populated_article(self, session, monkeypatch):
        _patch_fetcher(monkeypatch, PAGE)
        with TestClient(app) as client:
            r = client.post("/ingest/url", json={"url": PAGE_URL})
            assert r.status_code == 200 and r.json()["status"] == "ok"
        art = session.scalar(select(Article).where(Article.url == PAGE_URL))
        assert art.title == "Lumma campaign analysis"
        assert art.extracted_text
        assert session.scalar(select(Observable).where(Observable.normalized_value == "evil-c2.example.net"))

    async def test_untitled_page_gets_placeholder_not_empty_title(self, session, seed_source, monkeypatch):
        _patch_fetcher(monkeypatch, "<html><body><p>" + PARAGRAPH * 5 + "</p></body></html>")
        art = await IngestionEngine(session).ingest_url(PAGE_URL, source_id=seed_source.id)
        assert art.title == "(no title)"
        assert art.extracted_text

    async def test_source_pointing_at_one_page_is_parsed_too(self, session, monkeypatch):
        src = Source(
            name="One page",
            type="vendor_blog",
            url=PAGE_URL,
            enabled=True,
            baseline_confidence=80,
            collection_policy="safe_public_web",
        )
        session.add(src)
        session.commit()
        _patch_fetcher(monkeypatch, PAGE)
        res = await IngestionEngine(session).ingest_source(src)
        assert res["articles"] == 1
        art = session.scalar(select(Article).where(Article.url == PAGE_URL))
        assert art.title == "Lumma campaign analysis" and "evil-c2.example.net" in art.extracted_text

    async def test_metadata_only_sources_keep_no_page_content(self, session, monkeypatch):
        src = Source(
            name="Repo",
            type="github_repo",
            url=PAGE_URL,
            enabled=True,
            baseline_confidence=60,
            collection_policy="metadata_only",
        )
        session.add(src)
        session.commit()
        _patch_fetcher(monkeypatch, PAGE)
        art = await IngestionEngine(session).ingest_url(PAGE_URL, source_id=src.id)
        assert art.title == "Lumma campaign analysis"  # metadata is fine
        assert art.extracted_text == "" and art.raw_html is None  # content is not

    async def test_duplicate_url_returns_existing_article(self, session, seed_source, monkeypatch):
        _patch_fetcher(monkeypatch, PAGE)
        engine = IngestionEngine(session)
        first = await engine.ingest_url(PAGE_URL, source_id=seed_source.id)
        second = await engine.ingest_url(PAGE_URL, source_id=seed_source.id)
        assert first.id == second.id
        assert len(session.scalars(select(Article)).all()) == 1


class TestFeedSniffing:
    def test_looks_like_feed(self):
        assert looks_like_feed("application/rss+xml", "")
        assert looks_like_feed("text/html", RSS)  # wrong content-type, RSS body
        assert looks_like_feed("", "﻿  \n<?xml version='1.0'?><feed/>")
        assert looks_like_feed("text/plain", "<feed xmlns='http://www.w3.org/2005/Atom'></feed>")
        assert looks_like_feed("text/html", "<rdf:RDF></rdf:RDF>")
        assert not looks_like_feed("text/html", PAGE)
        assert not looks_like_feed("text/html", "")

    async def test_feed_served_as_html_is_ingested_as_a_feed_not_one_article(
        self, session, seed_source, monkeypatch
    ):
        _patch_fetcher(monkeypatch, RSS, url="https://example.com/blog/feed", content_type="text/html")
        res = await IngestionEngine(session).ingest_source(seed_source)
        assert res["articles"] == 2
        urls = {a.url for a in session.scalars(select(Article)).all()}
        assert urls == {"https://example.com/p1", "https://example.com/p2"}  # no article for the feed URL
