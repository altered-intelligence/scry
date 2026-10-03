"""Tests for v0.7.0 step 1: Sources under Intel Feeds with admin-only toggles.

Covers the Sources page rendering (admin sees live checkboxes, standard
users see greyed checkboxes with the admin-only hover message), the
admin-only POST /ui/sources/{id}/toggle (CSRF + audit), the
sync_from_yaml fix so runtime toggles survive a re-sync, and the 9 new
vendor-blog sources loading from config/sources.yaml.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select

from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE
from scry.db import session_scope
from scry.ingestion.source_registry import SourceRegistry
from scry.main import _admin_csrf_token, app
from scry.models import AuditLog, Source, User

PASSWORD = "S3cure!pass"

NEW_BLOGS = [
    "Cisco Talos Blog",
    "SOCRadar Blog",
    "The DFIR Report",
    "Securelist",
    "Krebs on Security",
    "SentinelOne Labs",
    "Red Canary Blog",
    "Rapid7 Blog",
    "Huntress Blog",
]

ADMIN_ONLY_TITLE = "Only admin users can toggle sources on/off"


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


def sync_sources() -> None:
    """Sync config/sources.yaml into the test DB (idempotent upsert)."""
    with session_scope() as s:
        SourceRegistry(s).sync_from_yaml()


def client_as(username: str, role: str = "user") -> TestClient:
    make_user(username, role=role)
    sync_sources()
    client = TestClient(app)
    login(client, username)
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


def source_id(name: str) -> int:
    with session_scope() as s:
        return s.scalar(select(Source.id).where(Source.name == name))


def enabled_in_db(source_pk: int) -> bool:
    with session_scope() as s:
        return s.scalar(select(Source.enabled).where(Source.id == source_pk))


# ------------------------- page rendering -------------------------


class TestSourcesPageRendering:
    def test_requires_login_when_users_exist(self):
        make_user("alice")
        with TestClient(app) as client:
            r = client.get("/ui/sources", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"

    def test_admin_sees_live_checkboxes(self):
        client = client_as("root", role="admin")
        r = client.get("/ui/sources")
        assert r.status_code == 200
        assert "/ui/sources/" in r.text and "/toggle" in r.text
        # live (submittable) checkboxes carry no disabled attribute
        assert 'name="csrf"' in r.text
        assert "<form" in r.text
        # no greyed-admin-only hint for admins
        assert ADMIN_ONLY_TITLE not in r.text
        # global-collection hint + enabled/total counts
        assert "Collection is global" in r.text
        assert "37 total" in r.text
        assert "enabled" in r.text

    def test_standard_user_sees_greyed_checkboxes_with_hover_message(self):
        client = client_as("bob")
        r = client.get("/ui/sources")
        assert r.status_code == 200
        assert ADMIN_ONLY_TITLE in r.text
        # greyed: at least one disabled checkbox, wrapped in a titled span
        assert 'type="checkbox" disabled' in r.text
        assert f'<span title="{ADMIN_ONLY_TITLE}">' in r.text
        # no live toggle forms for standard users
        assert "/toggle" not in r.text
        # read-only page still shows state + global hint
        assert "Collection is global" in r.text

    def test_local_import_origins_hidden_from_page_but_kept_in_db(self):
        """v0.15.0 — one-time bulk-import origins (local:// URLs, e.g. WEF Atlas
        workbooks) are not recurring feeds: hidden from the Sources GUI, kept
        in the DB for data lineage (articles/observables stay intact)."""
        client = client_as("carol", role="admin")
        with session_scope() as s:
            s.add(
                Source(
                    name="WEF Atlas Test Hunt (Local Import)",
                    type="local_file",
                    url="local://wef-atlas-test",
                    enabled=False,
                )
            )
        r = client.get("/ui/sources")
        assert r.status_code == 200
        assert "WEF Atlas Test Hunt" not in r.text
        with session_scope() as s:
            row = s.scalar(select(Source).where(Source.url == "local://wef-atlas-test"))
            assert row is not None  # lineage row survives
            s.delete(row)


# ------------------------- toggle route -------------------------


class TestSourceToggle:
    def test_admin_toggle_flips_db_and_flashes(self):
        client = client_as("root", role="admin")
        sid = source_id("CISA KEV")
        assert enabled_in_db(sid) is True
        r = client.post(f"/ui/sources/{sid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/ui/sources")
        assert "CISA KEV" in flash_of(r)
        assert "disabled" in flash_of(r)
        assert enabled_in_db(sid) is False
        # audit entry recorded
        with session_scope() as s:
            entry = s.scalar(select(AuditLog).where(AuditLog.action == "source.toggle"))
            assert entry is not None
            assert entry.actor == "root"
            assert entry.target_type == "source"
            assert entry.target_id == sid
            assert entry.detail["name"] == "CISA KEV"
            assert entry.detail["enabled"] is False

    def test_admin_toggle_back_on(self):
        client = client_as("root", role="admin")
        sid = source_id("Sophos X-Ops")
        assert enabled_in_db(sid) is False
        r = client.post(f"/ui/sources/{sid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert r.status_code == 303
        assert "enabled" in flash_of(r)
        assert enabled_in_db(sid) is True

    def test_standard_user_post_gets_403(self):
        client = client_as("bob")
        sid = source_id("CISA KEV")
        r = client.post(f"/ui/sources/{sid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert r.status_code == 403
        assert "Admins only" in r.text
        assert enabled_in_db(sid) is True  # unchanged

    def test_anonymous_post_redirects_to_login(self):
        make_user("alice")
        sync_sources()
        sid = source_id("CISA KEV")
        with TestClient(app) as client:
            r = client.post(f"/ui/sources/{sid}/toggle", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"
        assert enabled_in_db(sid) is True  # unchanged

    def test_bad_csrf_rejected(self):
        client = client_as("root", role="admin")
        sid = source_id("CISA KEV")
        r = client.post(f"/ui/sources/{sid}/toggle", data={"csrf": "bogus"}, follow_redirects=False)
        assert r.status_code == 303
        assert "CSRF" in flash_of(r)
        assert enabled_in_db(sid) is True  # unchanged

    def test_unknown_source(self):
        client = client_as("root", role="admin")
        r = client.post("/ui/sources/99999/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert r.status_code == 303
        assert "Unknown source" in flash_of(r)

    def test_toggle_survives_resync(self):
        """The registry sync must not clobber runtime toggles (the v0.7.0 fix)."""
        client = client_as("root", role="admin")
        sid = source_id("CISA KEV")
        client.post(f"/ui/sources/{sid}/toggle", data={"csrf": csrf_for(client)})
        assert enabled_in_db(sid) is False
        with session_scope() as s:
            SourceRegistry(s).sync_from_yaml()
        assert enabled_in_db(sid) is False  # yaml says enabled: true — must not clobber
        client.post(f"/ui/sources/{sid}/toggle", data={"csrf": csrf_for(client)})
        assert enabled_in_db(sid) is True


# ------------------------- sync fix (unit level) -------------------------


class TestSyncPreservesRuntimeEnabled:
    def test_yaml_enabled_applies_only_at_creation(self, session):
        SourceRegistry(session).sync_from_yaml()
        kev = session.scalar(select(Source).where(Source.name == "CISA KEV"))
        assert kev.enabled is True
        kev.enabled = False  # runtime toggle off (yaml still says enabled: true)
        session.flush()
        SourceRegistry(session).sync_from_yaml()
        session.expire_all()
        assert kev.enabled is False

    def test_yaml_enabled_on_at_creation(self, session):
        SourceRegistry(session).sync_from_yaml()
        kev = session.scalar(select(Source).where(Source.name == "CISA KEV"))
        kev.enabled = False
        session.flush()
        # deleting + resyncing recreates the row → yaml value applies again
        session.delete(kev)
        session.flush()
        SourceRegistry(session).sync_from_yaml()
        kev2 = session.scalar(select(Source).where(Source.name == "CISA KEV"))
        assert kev2.enabled is True

    def test_other_fields_keep_syncing(self, session):
        SourceRegistry(session).sync_from_yaml()
        kev = session.scalar(select(Source).where(Source.name == "CISA KEV"))
        original_confidence = kev.baseline_confidence
        kev.baseline_confidence = 1
        session.flush()
        SourceRegistry(session).sync_from_yaml()
        session.expire_all()
        assert kev.baseline_confidence == original_confidence  # synced back from yaml


# ------------------------- new vendor blogs -------------------------


class TestNewVendorBlogs:
    def test_all_nine_load_enabled(self, session):
        res = SourceRegistry(session).sync_from_yaml()
        assert res["added"] >= 9
        for name in NEW_BLOGS:
            src = session.scalar(select(Source).where(Source.name == name))
            assert src is not None, f"missing source: {name}"
            assert src.type == "vendor_blog"
            assert src.enabled is True
            assert src.priority == "high"
            assert 85 <= src.baseline_confidence <= 93
            assert src.collection_policy == "safe_public_web"
            assert src.independent is True
            assert src.rate_limit_per_minute == 10
            assert src.feed, f"{name} must carry a validated feed URL"

    def test_no_duplicates_of_existing_blogs(self, session):
        SourceRegistry(session).sync_from_yaml()
        names = [s.name for s in session.scalars(select(Source))]
        for dup in ("CrowdStrike", "Fortinet", "Unit 42", "Check Point", "Mandiant", "Microsoft"):
            matches = [n for n in names if dup in n]
            assert len(matches) == 1, f"duplicate source for {dup}: {matches}"
        for name in NEW_BLOGS:
            assert names.count(name) == 1

    def test_feed_urls_are_the_validated_ones(self, session):
        SourceRegistry(session).sync_from_yaml()
        feeds = {s.name: s.feed for s in session.scalars(select(Source).where(Source.name.in_(NEW_BLOGS)))}
        # Talos + Rapid7: homepage-declared alternates (original candidates 404'd)
        assert feeds["Cisco Talos Blog"] == "https://blog.talosintelligence.com/rss/"
        assert feeds["Rapid7 Blog"] == "https://www.rapid7.com/rss.xml"
        assert feeds["SOCRadar Blog"] == "https://socradar.io/blog/feed/"
        assert feeds["The DFIR Report"] == "https://thedfirreport.com/feed/"
        assert feeds["Securelist"] == "https://securelist.com/feed/"
        assert feeds["Krebs on Security"] == "https://krebsonsecurity.com/feed/"
        assert feeds["SentinelOne Labs"] == "https://www.sentinelone.com/labs/feed/"
        assert feeds["Red Canary Blog"] == "https://redcanary.com/feed/"
        assert feeds["Huntress Blog"] == "https://www.huntress.com/blog/rss.xml"
