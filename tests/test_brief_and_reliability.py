"""Briefing quality, collection reliability and UI trust fixes (2026-10 review).

The daily report led with ingestion counts, repeated stories, and dumped raw
fetch errors; feeds that answered HTTP 429 were retried every cycle; KEV
"new" counts used the row's update time; internal labels such as
urgent_review leaked into the UI; system-key save controls showed to every
user.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import scry.ingestion.ingest_engine as ingest_engine_module
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.ingestion.ingest_engine import _parse_kev_date
from scry.models import CVE, Article, Observable, Source, SourceFetch
from scry.reporting.common import rank_stories
from scry.reporting.daily import generate_daily_report
from scry.reporting.weekly import generate_weekly_report

NOW = datetime.now(UTC)


def _fetch(session, source, *, status, error, minutes_ago, url=None):
    session.add(
        SourceFetch(
            source_id=source.id,
            fetched_at=NOW - timedelta(minutes=minutes_ago),
            status_code=status,
            url=url or source.feed,
            error=error,
        )
    )
    session.commit()


# ---------------------------------------------------------------- reliability


class TestRateLimitCooldown:
    def test_no_throttle_no_cooldown(self, session, seed_source):
        _fetch(session, seed_source, status=200, error=None, minutes_ago=5)
        assert IngestionEngine(session).throttled_until(seed_source) is None

    def test_one_429_pauses_for_an_hour(self, session, seed_source):
        _fetch(session, seed_source, status=429, error="HTTP 429 after 3 attempts", minutes_ago=10)
        until = IngestionEngine(session).throttled_until(seed_source)
        assert until is not None and timedelta(minutes=45) < until - NOW <= timedelta(minutes=50)

    def test_consecutive_throttles_double_the_pause(self, session, seed_source):
        for minutes in (200, 100, 10):
            _fetch(session, seed_source, status=429, error="HTTP 429", minutes_ago=minutes)
        until = IngestionEngine(session).throttled_until(seed_source)
        assert until is not None and until - NOW > timedelta(hours=3)

    def test_success_ends_the_streak(self, session, seed_source):
        _fetch(session, seed_source, status=429, error="HTTP 429", minutes_ago=20)
        _fetch(session, seed_source, status=200, error=None, minutes_ago=10)
        assert IngestionEngine(session).throttled_until(seed_source) is None

    def test_article_page_throttles_do_not_pause_the_feed(self, session, seed_source):
        _fetch(
            session, seed_source, status=429, error="HTTP 429", minutes_ago=5, url="https://example.com/p/1"
        )
        assert IngestionEngine(session).throttled_until(seed_source) is None

    async def test_ingest_all_defers_a_throttled_source(self, session, seed_source, monkeypatch):
        _fetch(session, seed_source, status=429, error="HTTP 429", minutes_ago=5)
        calls = []

        async def fake_ingest(self, source):
            calls.append(source.name)
            return {"articles": 0}

        monkeypatch.setattr(IngestionEngine, "ingest_source", fake_ingest)
        totals = await IngestionEngine(session).ingest_all()
        assert totals["deferred"] == 1 and calls == []


class _Fetcher:
    calls: ClassVar[list[str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def fetch(self, url, *, policy=None, rate_limit_per_minute=10):
        type(self).calls.append(url)
        return FetchResult(url=url, status_code=429, error="HTTP 429 after 3 attempts")


async def test_full_fetch_stops_hitting_a_host_that_throttled(session, seed_source, monkeypatch):
    for i in range(4):
        session.add(
            Article(
                source_id=seed_source.id,
                title=f"stub {i}",
                url=f"https://slow.example.com/post/{i}",
                ingested_at=NOW,
                extracted_text="short",
            )
        )
    session.commit()
    _Fetcher.calls = []
    monkeypatch.setattr(ingest_engine_module, "SafeFetcher", _Fetcher)
    res = await IngestionEngine(session).fetch_full_content(limit=10)
    assert len(_Fetcher.calls) == 1
    assert res["failed"] == 1 and res["skipped"] == 3


class TestKevDates:
    def test_parse(self):
        assert _parse_kev_date("2026-10-02") == datetime(2026, 10, 2, tzinfo=UTC)
        assert _parse_kev_date(None) is None and _parse_kev_date("garbage") is None

    def test_kev_ingest_stores_date_added(self, session):
        body = (
            '{"vulnerabilities": [{"cveID": "CVE-2026-1", "vendorProject": "Acme", "product": "Box",'
            ' "shortDescription": "bad", "dateAdded": "2026-10-01", "knownRansomwareCampaignUse": "Known"}]}'
        )
        IngestionEngine(session)._persist_kev(body)
        cve = session.scalar(select(CVE).where(CVE.cve_id == "CVE-2026-1"))
        assert cve.kev_added_at.date().isoformat() == "2026-10-01"


# ---------------------------------------------------------------- briefs


def _art(session, source, title, url, text="", tags=None):
    a = Article(
        source_id=source.id,
        title=title,
        url=url,
        ingested_at=NOW - timedelta(hours=1),
        extracted_text=text,
        tags=tags or [],
        source_confidence=80,
    )
    session.add(a)
    session.commit()
    return a


@pytest.fixture
def pulse_source(session):
    src = Source(name="OTX pulses", type="otx_pulse", url="", enabled=True)
    session.add(src)
    session.commit()
    return src


class TestDailyBrief:
    def test_leads_with_what_changed_why_and_actions(self, session, seed_source):
        text = generate_daily_report(session)
        assert text.startswith("# Scry Daily Threat Brief")
        order = [text.index(h) for h in ("## What changed", "## Why it matters", "## Recommended actions")]
        assert order == sorted(order)

    def test_same_event_from_two_outlets_is_one_story(self, session, seed_source):
        other = Source(name="Other News", type="news", url="https://other.example", enabled=True)
        session.add(other)
        session.commit()
        _art(
            session,
            seed_source,
            "ShinyHunters hacker reportedly detained in Jordan, aiding FBI",
            "https://a/1",
        )
        _art(session, other, "ShinyHunters Suspect Reportedly Detained in Jordan, Helping FBI", "https://b/1")
        stories, _ = rank_stories(session.scalars(select(Article)).all(), [])
        assert len(stories) == 1
        headline = stories[0].article.source.name
        assert {headline, *stories[0].also_reported_by} == {"Test Vendor Blog", "Other News"}

    def test_repeated_feed_titles_collapse(self, session, seed_source):
        _art(session, seed_source, "VoidTrap Live Threat Feed — 2026-10-04", "https://a/1")
        _art(session, seed_source, "VoidTrap Live Threat Feed — 2026-10-05", "https://a/2")
        stories, _ = rank_stories(session.scalars(select(Article)).all(), [])
        assert len(stories) == 1 and stories[0].repeats == 2

    def test_automated_records_and_index_pages_are_not_stories(self, session, seed_source, pulse_source):
        _art(session, pulse_source, "Honeynet capture: session from 1.2.3.4", "https://otx/1")
        _art(session, seed_source, "Vendor Blog", seed_source.feed)
        stories, automated = rank_stories(session.scalars(select(Article)).all(), [])
        assert stories == [] and automated == 1

    def test_missing_title_gets_a_readable_fallback(self, session, seed_source):
        _art(session, seed_source, "(no title)", "https://news.example.net/story")
        assert "Untitled article (news.example.net)" in generate_daily_report(session)

    def test_collection_problems_are_summarised_per_source(self, session, seed_source):
        for m in (30, 20, 10):
            _fetch(session, seed_source, status=429, error="HTTP 429 after 3 attempts", minutes_ago=m)
        text = generate_daily_report(session)
        section = text.split("## Collection health", 1)[1]
        assert "**Test Vendor Blog**: rate limited (HTTP 429) (3 times)" in section
        assert "paused until" in section
        assert "source_id=" not in text and "error=" not in text

    def test_new_kev_uses_date_added_not_row_update(self, session, seed_source):
        session.add_all(
            [
                CVE(cve_id="CVE-2026-0001", kev=True, kev_added_at=NOW - timedelta(hours=2), vendor="Acme"),
                CVE(cve_id="CVE-2019-0002", kev=True, kev_added_at=NOW - timedelta(days=900), vendor="Old"),
            ]
        )
        session.commit()
        text = generate_daily_report(session)
        assert "CVE-2026-0001" in text and "CVE-2019-0002" not in text

    def test_indicators_use_readable_actions(self, session, seed_source):
        session.add(
            Observable(
                type="domain",
                value="bad.example",
                normalized_value="bad.example",
                validation_status="valid",
                extraction_confidence=80,
                maliciousness_confidence=70,
                false_positive_risk=0.0,
                risk_score=90,
                actionability="urgent_review",
                status="active",
                ttl_days=30,
                enrichment={},
                tags=["malicious-context"],
                scoring_model_version="0.2",
                last_seen=NOW,
            )
        )
        session.commit()
        text = generate_daily_report(session)
        assert "Urgent review" in text and "urgent_review" not in text

    def test_weekly_brief_has_title_and_priorities(self, session, seed_source):
        text = generate_weekly_report(session)
        assert text.startswith("# Scry Weekly Threat Brief")
        assert "## Priorities for next week" in text


# ---------------------------------------------------------------- UI


PASSWORD = "S3cure!pass"


def _user(username, role):
    from scry.auth.passwords import hash_password
    from scry.db import session_scope
    from scry.models import User

    with session_scope() as s:
        s.add(
            User(
                username=username,
                email=f"{username}@x.test",
                role=role,
                password_hash=hash_password(PASSWORD),
            )
        )


def _client(username):
    from scry.main import app

    client = TestClient(app)
    client.post("/login", data={"username": username, "password": PASSWORD}, follow_redirects=False)
    return client


class TestUi:
    def test_system_key_controls_are_admin_only(self):
        _user("root", "admin")
        _user("ana", "user")
        assert "enrich-save" in _client("root").get("/ui/alerts").text
        page = _client("ana").get("/ui/alerts").text
        assert 'class="btn enrich-save"' not in page and "admin only" in page

    def test_dashboard_explains_extraction_and_ai(self):
        page = TestClient(__import__("scry.main", fromlist=["app"]).app).get("/").text
        assert "rule-based" in page and "LLM provider" not in page

    def test_observable_page_explains_the_score(self, session, seed_source):
        from scry.pipeline import CTIPipeline

        art = _art(
            session, seed_source, "t", "https://example.com/x", text="The implant beacons to c2-relay.com."
        )
        CTIPipeline(session).process_article(art)
        ob = session.scalar(select(Observable).where(Observable.normalized_value == "c2-relay.com"))
        page = TestClient(__import__("scry.main", fromlist=["app"]).app).get(f"/ui/observables/{ob.id}").text
        assert "How this score was built" in page and "Source reliability" in page
        assert "not assessed" in page  # no benign signal evaluated: not a measured zero
