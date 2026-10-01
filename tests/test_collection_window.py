"""Tests for v0.7.0 step 2: the collection window (1-7 days, admin-only).

Covers the collection_window module (get/set/clamp/default,
entry_in_window edge cases), the ingest-engine integration (old entries
skipped, new + undated kept, window_skipped counted), the admin-only
POST /admin/collection-window/save (CSRF, audit, clamping), and the
read-only line on the Sources page.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE
from scry.db import session_scope
from scry.ingestion import ingest_engine as ingest_engine_module
from scry.ingestion.collection_window import (
    entry_in_window,
    get_window_days,
    set_window_days,
)
from scry.ingestion.fetcher import FetchResult
from scry.ingestion.ingest_engine import IngestionEngine
from scry.main import _admin_csrf_token, app
from scry.models import Article, AuditLog, SystemSetting, User

PASSWORD = "S3cure!pass"


def make_user(username: str, role: str = "user") -> None:
    with session_scope() as s:
        s.add(
            User(
                username=username,
                email=f"{username}@example.com",
                role=role,
                status="active",
                password_hash=hash_password(PASSWORD),
            )
        )


def login(client: TestClient, username: str) -> None:
    client.post("/login", data={"username": username, "password": PASSWORD})


def client_as(username: str, role: str = "user") -> TestClient:
    make_user(username, role=role)
    client = TestClient(app)
    login(client, username)
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


# ------------------------- get/set/clamp/default -------------------------


class TestWindowDaysSetting:
    def test_default_is_one_when_unset(self, session: Session):
        assert get_window_days(session) == 1

    def test_set_and_get(self, session: Session):
        assert set_window_days(session, 5) == 5
        assert get_window_days(session) == 5

    def test_set_updates_existing_row(self, session: Session):
        set_window_days(session, 3)
        assert set_window_days(session, 2) == 2
        rows = session.scalars(
            select(SystemSetting).where(SystemSetting.key == "collection_window_days")
        ).all()
        assert len(rows) == 1
        assert rows[0].value == "2"

    def test_set_clamps_low(self, session: Session):
        assert set_window_days(session, 0) == 1
        assert get_window_days(session) == 1

    def test_set_clamps_high(self, session: Session):
        assert set_window_days(session, 99) == 7
        assert get_window_days(session) == 7

    def test_get_clamps_bad_stored_values(self, session: Session):
        session.add(SystemSetting(key="collection_window_days", value="0"))
        session.flush()
        assert get_window_days(session) == 1
        session.execute(
            update(SystemSetting).where(SystemSetting.key == "collection_window_days").values(value="99")
        )
        session.flush()
        assert get_window_days(session) == 7

    def test_get_defaults_on_garbage(self, session: Session):
        session.add(SystemSetting(key="collection_window_days", value="junk"))
        session.flush()
        assert get_window_days(session) == 1


# ------------------------- entry_in_window -------------------------


class TestEntryInWindow:
    NOW = datetime(2026, 10, 5, 12, 0, tzinfo=UTC)

    def test_none_date_always_kept(self):
        assert entry_in_window(None, 1, self.NOW) is True

    def test_recent_entry_kept(self):
        published = self.NOW - timedelta(hours=12)
        assert entry_in_window(published, 1, self.NOW) is True

    def test_old_entry_skipped(self):
        published = self.NOW - timedelta(days=3)
        assert entry_in_window(published, 1, self.NOW) is False

    def test_boundary_is_inclusive(self):
        # Exactly now - N days is kept; the window is [now-N days, now].
        published = self.NOW - timedelta(days=2)
        assert entry_in_window(published, 2, self.NOW) is True
        published = self.NOW - timedelta(days=2, microseconds=1)
        assert entry_in_window(published, 2, self.NOW) is False

    def test_naive_datetimes_treated_as_utc(self):
        published = datetime(2026, 10, 4, 12, 0)  # naive == UTC here
        assert entry_in_window(published, 1, self.NOW) is True
        naive_now = datetime(2026, 10, 5, 12, 0)
        assert entry_in_window(self.NOW - timedelta(hours=1), 1, naive_now) is True

    def test_aware_vs_naive_mix(self):
        published = datetime(2026, 10, 4, 0, 0)  # naive, 36h before NOW
        assert entry_in_window(published, 1, self.NOW) is False
        assert entry_in_window(published, 7, self.NOW) is True


# ------------------------- engine integration -------------------------


def _rss_text(pub_dates: dict[str, datetime | None]) -> str:
    items = []
    for slug, published in pub_dates.items():
        date_xml = f"<pubDate>{format_datetime(published)}</pubDate>" if published is not None else ""
        items.append(f"<item><title>{slug}</title><link>https://example.com/{slug}</link>{date_xml}</item>")
    return (
        '<?xml version="1.0"?>\n<rss version="2.0"><channel>'
        "<title>test</title><link>https://example.com/</link><description>d</description>"
        + "".join(items)
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


class TestEngineWindowFiltering:
    async def test_old_skipped_new_and_undated_kept(self, session: Session, seed_source, monkeypatch):
        now = datetime.now(UTC)
        text = _rss_text(
            {
                "old": now - timedelta(days=5),
                "fresh": now - timedelta(hours=2),
                "undated": None,
            }
        )
        _patch_fetcher(monkeypatch, text)
        engine = IngestionEngine(session)
        res = await engine.ingest_source(seed_source)
        assert res["articles"] == 2
        assert res["window_skipped"] == 1
        urls = {a.url for a in session.scalars(select(Article)).all()}
        assert urls == {"https://example.com/fresh", "https://example.com/undated"}

    async def test_window_days_respected(self, session: Session, seed_source, monkeypatch):
        set_window_days(session, 7)
        now = datetime.now(UTC)
        text = _rss_text(
            {
                "d5": now - timedelta(days=5),
                "d9": now - timedelta(days=9),
            }
        )
        _patch_fetcher(monkeypatch, text)
        engine = IngestionEngine(session)
        res = await engine.ingest_source(seed_source)
        assert res["articles"] == 1
        assert res["window_skipped"] == 1
        urls = {a.url for a in session.scalars(select(Article)).all()}
        assert urls == {"https://example.com/d5"}

    async def test_all_undated_feed_unchanged(self, session: Session, seed_source, monkeypatch):
        """Feeds without any dates keep collecting (default window=1)."""
        text = _rss_text({"a": None, "b": None})
        _patch_fetcher(monkeypatch, text)
        engine = IngestionEngine(session)
        res = await engine.ingest_source(seed_source)
        assert res["articles"] == 2
        assert res["window_skipped"] == 0

    async def test_duplicate_url_check_after_window(self, session: Session, seed_source, monkeypatch):
        """A skipped old entry is not persisted, so re-ingest stays stable."""
        now = datetime.now(UTC)
        text = _rss_text({"old": now - timedelta(days=5), "fresh": now - timedelta(hours=1)})
        _patch_fetcher(monkeypatch, text)
        engine = IngestionEngine(session)
        await engine.ingest_source(seed_source)
        res = await engine.ingest_source(seed_source)
        assert res["articles"] == 0  # fresh now a duplicate; old still out of window
        assert res["window_skipped"] == 1


# ------------------------- admin route -------------------------


class TestAdminCollectionWindow:
    def test_admin_save_sets_value_and_audits(self):
        client = client_as("root", role="admin")
        r = client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "3"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "last 3 day" in flash_of(r)
        with session_scope() as s:
            assert get_window_days(s) == 3
            entry = s.scalar(select(AuditLog).where(AuditLog.action == "collection_window.set"))
            assert entry is not None
            assert entry.actor == "root"
            assert entry.detail["days"] == 3

    def test_standard_user_post_gets_403(self):
        client = client_as("bob")
        r = client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "3"},
            follow_redirects=False,
        )
        assert r.status_code == 403
        with session_scope() as s:
            assert get_window_days(s) == 1  # unchanged

    def test_anonymous_post_redirects_to_login(self):
        make_user("alice")
        with TestClient(app) as client:
            r = client.post("/admin/collection-window/save", data={"days": "3"}, follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"

    def test_clamps_out_of_range_values(self):
        client = client_as("root", role="admin")
        r = client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "0"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        with session_scope() as s:
            assert get_window_days(s) == 1
        client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "99"},
            follow_redirects=False,
        )
        with session_scope() as s:
            assert get_window_days(s) == 7

    def test_bad_csrf_rejected(self):
        client = client_as("root", role="admin")
        r = client.post(
            "/admin/collection-window/save",
            data={"csrf": "bogus", "days": "3"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "CSRF" in flash_of(r)
        with session_scope() as s:
            assert get_window_days(s) == 1

    def test_non_numeric_rejected(self):
        client = client_as("root", role="admin")
        r = client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "abc"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "Invalid collection window" in flash_of(r)

    def test_admin_page_shows_current_value(self):
        client = client_as("root", role="admin")
        client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "4"},
            follow_redirects=False,
        )
        r = client.get("/admin")
        assert r.status_code == 200
        assert 'id="collection-window"' in r.text
        assert 'action="/admin/collection-window/save"' in r.text
        assert 'value="4"' in r.text


# ------------------------- sources page -------------------------


class TestSourcesPageWindowLine:
    def test_shows_default_window(self):
        client = client_as("bob")
        r = client.get("/ui/sources")
        assert r.status_code == 200
        assert "Collection window: last 1 day(s)" in r.text
        assert "admins can change this on the" in r.text

    def test_reflects_saved_window(self):
        client = client_as("root", role="admin")
        client.post(
            "/admin/collection-window/save",
            data={"csrf": csrf_for(client), "days": "6"},
            follow_redirects=False,
        )
        r = client.get("/ui/sources")
        assert r.status_code == 200
        assert "Collection window: last 6 day(s)" in r.text

    def test_no_window_form_for_anyone(self):
        """The Sources page is read-only for the window — no input there."""
        client = client_as("root", role="admin")
        r = client.get("/ui/sources")
        assert 'action="/admin/collection-window/save"' not in r.text
