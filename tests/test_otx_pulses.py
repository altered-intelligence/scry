"""Tests for v0.6.0 step 1: OTX pulse ingestion as a first-class source.

Covers subscription YAML loading/validation, respx-mocked search+pulse
pulls (article fields, URL dedup on re-pull, age/tag filters, limit),
key resolution (personal vs system vs none), the REST routes, the
scheduler job, the CLI, the threat-feeds UI section, and the guarantee
that key material never reaches the logs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE, create_session
from scry.cli import app as cli_app
from scry.config import get_settings
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import Article, Source, SystemSetting, User

PASSWORD = "S3cure!pass"
runner = CliRunner()

SEARCH_URL = "https://otx.alienvault.com/api/v1/search/pulses"

PERSONAL_OTX_KEY = "personal-otx-key-4567"
SYS_OTX_KEY = "system-otx-key"

NOW = datetime.now(UTC)
RECENT = NOW.isoformat()
OLD = "2020-01-01T00:00:00+00:00"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """Deterministic keys: neutralize the real .env OTX key by default."""
    monkeypatch.setenv("CTI_OTX_API_KEY", "")
    get_settings.cache_clear()


def make_user(username: str = "alice", role: str = "user") -> int:
    with session_scope() as s:
        user = User(
            username=username,
            email=f"{username}@example.com",
            role=role,
            status="active",
            password_hash=hash_password(PASSWORD),
        )
        s.add(user)
        s.flush()
        return user.id


def auth_client(username: str = "alice") -> TestClient:
    client = TestClient(app)
    with session_scope() as s:
        user = s.scalar(select(User).where(func.lower(User.username) == username.lower()))
        raw = create_session(s, user, ip="127.0.0.1", user_agent="pytest")
    client.cookies.set(SESSION_COOKIE, raw)
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


def pulse(pulse_id: str, *, created: str = RECENT, tags: list[str] | None = None, **kw) -> dict:
    base = {
        "id": pulse_id,
        "name": f"Pulse {pulse_id}",
        "description": f"Description for pulse {pulse_id}",
        "tags": tags if tags is not None else ["ransomware"],
        "created": created,
        "modified": created,
        "TLP": "white",
    }
    base.update(kw)
    return base


def sub(name: str = "ransomware", **kw):
    from scry.ingestion.otx_pulses import PulseSubscription

    return PulseSubscription(name=name, query=name, **kw)


def write_subs_yaml(tmp_path, subs: list[dict]) -> str:
    path = tmp_path / "otx_pulses.yaml"
    path.write_text(yaml.safe_dump({"subscriptions": subs}))
    return str(path)


def mock_search(payload: list[dict]) -> respx.Router:
    return respx.get(SEARCH_URL).mock(return_value=httpx.Response(200, json={"results": payload}))


# ------------------------- YAML loading + validation -------------------------


class TestLoadSubscriptions:
    def test_valid_with_defaults(self, tmp_path):
        from scry.ingestion.otx_pulses import (
            DEFAULT_LIMIT,
            DEFAULT_MAX_PULSE_AGE_DAYS,
            load_subscriptions,
        )

        path = write_subs_yaml(tmp_path, [{"name": "a", "query": "ransomware"}])
        subs = load_subscriptions(path)
        assert len(subs) == 1
        s = subs[0]
        assert s.name == "a" and s.query == "ransomware"
        assert s.tags == []
        assert s.max_pulse_age_days == DEFAULT_MAX_PULSE_AGE_DAYS
        assert s.limit == DEFAULT_LIMIT
        assert s.source_name == "otx_pulse:a"

    def test_full_spec(self, tmp_path):
        from scry.ingestion.otx_pulses import load_subscriptions

        path = write_subs_yaml(
            tmp_path,
            [
                {
                    "name": "b",
                    "query": "apt",
                    "tags": ["apt", "espionage"],
                    "max_pulse_age_days": 7,
                    "limit": 10,
                }
            ],
        )
        (s,) = load_subscriptions(path)
        assert s.tags == ["apt", "espionage"]
        assert s.max_pulse_age_days == 7
        assert s.limit == 10

    def test_invalid_entries_skipped(self, tmp_path):
        from scry.ingestion.otx_pulses import load_subscriptions

        path = write_subs_yaml(
            tmp_path,
            [
                {"name": "", "query": "x"},
                {"name": "noquery", "query": "   "},
                {"name": "badnum", "query": "x", "limit": "lots"},
                {"name": "badtags", "query": "x", "tags": "notalist"},
                "not-a-mapping",
                {"name": "good", "query": "ok"},
            ],
        )
        subs = load_subscriptions(path)
        assert [s.name for s in subs] == ["good"]

    def test_empty_file_gives_no_subscriptions(self, tmp_path):
        from scry.ingestion.otx_pulses import load_subscriptions

        path = write_subs_yaml(tmp_path, [])
        assert load_subscriptions(path) == []


# ------------------------- pull flows -------------------------


class TestPullSubscription:
    @respx.mock
    def test_creates_articles_with_expected_fields(self, session):
        route = mock_search(
            [
                pulse("p1", tags=["ransomware", "curated"]),
                pulse("p2", tags=["botnet", "curated"], name="Botnet ops"),
            ]
        )
        s = sub(tags=["curated"])

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)

        assert counts == {"added": 2, "skipped": 0, "updated": 0, "filtered": 0}
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == SYS_OTX_KEY
        assert "q=ransomware" in str(route.calls[0].request.url)

        articles = session.scalars(select(Article).order_by(Article.id)).all()
        assert len(articles) == 2
        a1 = articles[0]
        assert a1.url == "https://otx.alienvault.com/pulse/p1"
        assert a1.title == "Pulse p1"
        assert a1.summary == "Description for pulse p1"
        assert a1.published_at is not None
        assert set(a1.tags) == {"ransomware", "curated"}
        src = session.get(Source, a1.source_id)
        assert src.name == "otx_pulse:ransomware"
        assert src.enabled is False  # not an RSS source; ingest_all must skip it
        a2 = articles[1]
        assert set(a2.tags) == {"botnet", "curated"}

    @respx.mock
    def test_repull_is_idempotent_and_updates_changed_pulse(self, session):
        mock_search([pulse("p1"), pulse("p2")])
        s = sub()

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(SYS_OTX_KEY) as client:
            assert pull_subscription(client, s, session)["added"] == 2
            counts = pull_subscription(client, s, session)
            assert counts["skipped"] == 2 and counts["added"] == 0 and counts["updated"] == 0
            assert session.scalar(select(func.count(Article.id))) == 2

        # p1 changes description → updated; p2 unchanged → skipped
        mock_search([pulse("p1", description="New description"), pulse("p2")])
        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)
        assert counts["updated"] == 1 and counts["skipped"] == 1
        art = session.scalar(select(Article).where(Article.url.endswith("/pulse/p1")))
        assert art.summary == "New description"
        assert art.extractor_version == "0"  # reset so the pipeline re-runs

    @respx.mock
    def test_age_filter(self, session):
        mock_search([pulse("old", created=OLD), pulse("fresh", created=RECENT)])
        s = sub(max_pulse_age_days=30)

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)
        assert counts == {"added": 1, "skipped": 0, "updated": 0, "filtered": 1}
        art = session.scalar(select(Article))
        assert art.url.endswith("/pulse/fresh")

    @respx.mock
    def test_tag_filter(self, session):
        mock_search([pulse("t1", tags=["apt"]), pulse("t2", tags=["ransomware"])])
        s = sub(tags=["ransomware"])

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)
        assert counts["added"] == 1 and counts["filtered"] == 1
        art = session.scalar(select(Article))
        assert art.url.endswith("/pulse/t2")
        assert set(art.tags) == {"ransomware"}

    @respx.mock
    def test_tag_filter_case_insensitive(self, session):
        # OTX capitalizes many pulse tags ("Ransomware") — matching must be
        # case-insensitive (live incident 2026-09-30: an all-25-filtered pull).
        mock_search([pulse("t1", tags=["Ransomware"]), pulse("t2", tags=["APT"])])
        s = sub(tags=["ransomware"])

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)
        assert counts["added"] == 1 and counts["filtered"] == 1
        art = session.scalar(select(Article))
        assert art.url.endswith("/pulse/t1")

    @respx.mock
    def test_tag_filter_fetches_detail_when_search_omits_tags(self, session):
        # OTX search results always carry tags: [] — the pull must fetch the
        # pulse detail to evaluate a tag filter (same live incident).
        from scry.ingestion.otx_pulses import PULSE_DETAIL_URL, OTXPulseClient, pull_subscription

        mock_search([pulse("t1", tags=[]), pulse("t2", tags=[])])
        respx.get(PULSE_DETAIL_URL.format(pulse_id="t1")).mock(
            return_value=httpx.Response(200, json=pulse("t1", tags=["Ransomware"]))
        )
        respx.get(PULSE_DETAIL_URL.format(pulse_id="t2")).mock(
            return_value=httpx.Response(200, json=pulse("t2", tags=["apt"]))
        )
        s = sub(tags=["ransomware"])

        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)
        assert counts["added"] == 1 and counts["filtered"] == 1
        art = session.scalar(select(Article))
        assert art.url.endswith("/pulse/t1")
        assert "ransomware" in [t.lower() for t in art.tags]

    @respx.mock
    def test_limit_caps_results(self, session):
        mock_search([pulse(f"p{i}") for i in range(10)])
        s = sub(limit=3)

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(SYS_OTX_KEY) as client:
            counts = pull_subscription(client, s, session)
        assert counts["added"] == 3
        assert "limit=3" in str(respx.calls[0].request.url)

    @respx.mock
    def test_pull_all_continues_after_subscription_error(self, session):
        respx.get(SEARCH_URL).mock(side_effect=httpx.ConnectError("refused"))
        s1, s2 = sub("one"), sub("two")

        from scry.ingestion.otx_pulses import pull_all

        results = pull_all(session, api_key=SYS_OTX_KEY, subscriptions=[s1, s2])
        assert results["one"]["error"] == 1
        assert results["two"]["error"] == 1

    @respx.mock
    def test_last_run_stats_recorded(self, session):
        mock_search([pulse("p1")])
        s = sub()

        from scry.ingestion.otx_pulses import last_run_stats, pull_all

        assert last_run_stats(session, [s])["ransomware"] == {}
        pull_all(session, api_key=SYS_OTX_KEY, subscriptions=[s])
        stats = last_run_stats(session, [s])["ransomware"]
        assert stats["added"] == 1 and "at" in stats
        row = session.scalar(
            select(SystemSetting).where(SystemSetting.key == "otx_pulse.ransomware.last_run")
        )
        assert row is not None


# ------------------------- key resolution -------------------------


class TestKeyResolution:
    def test_user_with_personal_key_gets_personal_key(self, monkeypatch):
        from scry.enrichment.user_keys import set_key
        from scry.ingestion.otx_pulses import resolve_key

        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
            key, source = resolve_key(s, s.get(User, uid))
        assert key == PERSONAL_OTX_KEY and source == "personal"

    def test_user_without_personal_key_gets_nothing(self, monkeypatch):
        """User-triggered pulls never silently fall back to the system key."""
        from scry.ingestion.otx_pulses import resolve_key

        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        uid = make_user()
        with session_scope() as s:
            key, source = resolve_key(s, s.get(User, uid))
        assert key == "" and source == ""

    def test_no_acting_user_uses_system_key(self, monkeypatch):
        from scry.ingestion.otx_pulses import resolve_key

        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        with session_scope() as s:
            key, source = resolve_key(s, None)
        assert key == SYS_OTX_KEY and source == "system"

    def test_no_key_anywhere_is_clean_disabled(self):
        from scry.ingestion.otx_pulses import resolve_key

        with session_scope() as s:
            assert resolve_key(s, None) == ("", "")


# ------------------------- REST routes -------------------------


class TestApiRoutes:
    @respx.mock
    def test_pull_all_with_system_key_no_users(self, monkeypatch):
        """Zero users → legacy open API; system env key chain applies."""
        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        route = mock_search([pulse("p1")])

        client = TestClient(app)
        r = client.post("/ingest/otx-pulses")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["key_source"] == "system"
        assert body["results"]["ransomware"]["added"] == 1
        assert body["pipeline_processed"] >= 1
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == SYS_OTX_KEY

    @respx.mock
    def test_no_key_returns_clean_disabled(self):
        client = TestClient(app)
        r = client.post("/ingest/otx-pulses")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "disabled"
        assert "OTX" in body["reason"]
        assert body["results"] == {}

    @respx.mock
    def test_acting_user_personal_key_used(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        route = mock_search([pulse("p1")])

        client = auth_client()
        r = client.post("/ingest/otx-pulses")
        assert r.status_code == 200
        assert r.json()["key_source"] == "personal"
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == PERSONAL_OTX_KEY

    @respx.mock
    def test_acting_user_without_personal_key_disabled(self, monkeypatch):
        """Personal-key rule: no fallback to the system key for user pulls."""
        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        make_user()
        route = mock_search([pulse("p1")])

        client = auth_client()
        r = client.post("/ingest/otx-pulses")
        assert r.json()["status"] == "disabled"
        assert "personal" in r.json()["reason"]
        assert not route.called

    @respx.mock
    def test_subscription_filter_and_unknown_name(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        route = mock_search([pulse("p1")])

        client = auth_client()
        r = client.post("/ingest/otx-pulses", json={"subscriptions": ["ransomware"]})
        assert r.status_code == 200
        assert list(r.json()["results"]) == ["ransomware"]
        assert route.called

        r = client.post("/ingest/otx-pulses", json={"subscriptions": ["nope"]})
        assert r.status_code == 400

    @respx.mock
    def test_requires_auth_when_users_exist(self):
        make_user()
        client = TestClient(app)
        r = client.post("/ingest/otx-pulses")
        assert r.status_code == 401

    def test_subscriptions_listing_with_last_run(self):
        from scry.enrichment.user_keys import set_key
        from scry.ingestion.otx_pulses import record_last_run

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
            record_last_run(s, sub(), {"added": 3, "skipped": 1, "updated": 0, "filtered": 2})

        client = auth_client()
        r = client.get("/ingest/otx-pulses/subscriptions")
        assert r.status_code == 200
        entries = {e["name"]: e for e in r.json()["subscriptions"]}
        entry = entries["ransomware"]
        assert entry["query"] == "ransomware"
        assert entry["limit"] == 25 and entry["max_pulse_age_days"] == 30
        assert entry["last_run"]["added"] == 3


# ------------------------- scheduler -------------------------


class TestScheduler:
    @respx.mock
    def test_otx_job_registered(self, monkeypatch):
        import scry.scheduler as sched_mod

        added = []

        class _FakeSched:
            def __init__(self, *a, **k):
                pass

            def add_job(self, fn, trigger, **kw):
                added.append(kw.get("id"))

            def start(self):
                pass

        monkeypatch.setattr(sched_mod, "BlockingScheduler", _FakeSched)
        sched_mod.main()
        assert "otx_pulses" in added

    def test_otx_job_uses_system_key_and_never_raises(self, monkeypatch):
        import scry.scheduler as sched_mod

        monkeypatch.setenv("CTI_OTX_API_KEY", "")
        get_settings.cache_clear()
        sched_mod._otx_pulses_job()  # no key → clean skip, no exception

        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        seen = {}

        def _fake_pull_all(session, *, api_key, subscriptions=None):
            seen["api_key"] = api_key
            return {"ransomware": {"added": 1, "skipped": 0, "updated": 0, "filtered": 0}}

        monkeypatch.setattr(sched_mod, "pull_all", _fake_pull_all)
        sched_mod._otx_pulses_job()
        assert seen["api_key"] == SYS_OTX_KEY


# ------------------------- CLI -------------------------


class TestCli:
    @respx.mock
    def test_pull_with_system_key(self, monkeypatch):
        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        route = mock_search([pulse("p1")])

        result = runner.invoke(cli_app, ["ingest", "otx-pulses"])
        assert result.exit_code == 0, result.output
        assert '"added": 1' in result.output
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == SYS_OTX_KEY
        assert SYS_OTX_KEY not in result.output

    def test_disabled_without_key(self, monkeypatch):
        monkeypatch.setenv("CTI_OTX_API_KEY", "")
        get_settings.cache_clear()
        result = runner.invoke(cli_app, ["ingest", "otx-pulses"])
        assert result.exit_code == 0
        assert "disabled" in result.output

    def test_unknown_subscription_errors(self, monkeypatch):
        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        result = runner.invoke(cli_app, ["ingest", "otx-pulses", "--subscriptions", "nope"])
        assert result.exit_code == 2

    @respx.mock
    def test_subscription_filter(self, monkeypatch):
        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        route = mock_search([pulse("p1")])

        result = runner.invoke(cli_app, ["ingest", "otx-pulses", "--subscriptions", "ransomware"])
        assert result.exit_code == 0, result.output
        assert route.called


# ------------------------- UI -------------------------


class TestUi:
    def test_page_shows_subscriptions_section(self):
        make_user()
        client = auth_client()
        r = client.get("/ui/intel-feeds/threat-feeds")
        assert r.status_code == 200
        assert "OTX pulse subscriptions" in r.text
        assert "ransomware" in r.text
        assert "Pull now" in r.text
        assert "Pull all subscriptions" in r.text

    @respx.mock
    def test_pull_now_with_personal_key_flashes_counts(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        route = mock_search([pulse("p1"), pulse("p2")])

        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/otx-pull",
            data={"csrf": csrf_for(client), "subscription": "ransomware"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        flash = flash_of(r)
        assert "added 2" in flash
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == PERSONAL_OTX_KEY

        # last-run stats now render on the page
        page = client.get("/ui/intel-feeds/threat-feeds")
        assert "Last pull" in page.text

    @respx.mock
    def test_pull_all_without_subscription_field(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        route = mock_search([pulse("p1")])

        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/otx-pull",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "added 1" in flash_of(r)
        assert route.called

    def test_pull_without_personal_key_flashes_disabled(self, monkeypatch):
        monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
        get_settings.cache_clear()
        make_user()
        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/otx-pull",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert "disabled" in flash_of(r)

    def test_bad_csrf_rejected(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/otx-pull",
            data={"csrf": "bogus"},
            follow_redirects=False,
        )
        assert "CSRF" in flash_of(r)

    def test_unknown_subscription_flashes_error(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/otx-pull",
            data={"csrf": csrf_for(client), "subscription": "nope"},
            follow_redirects=False,
        )
        assert "Unknown OTX pulse subscription" in flash_of(r)

    def test_anonymous_pull_redirects_to_login(self):
        make_user()
        client = TestClient(app)
        r = client.post("/ui/intel-feeds/otx-pull", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login")


# ------------------------- key never logged -------------------------


class TestKeyNeverLogged:
    @respx.mock
    def test_key_absent_from_logs_on_pull(self, session, capsys):
        secret = "sk-live-secret-key-999"
        route = mock_search([pulse("p1")])

        from scry.ingestion.otx_pulses import OTXPulseClient, pull_subscription

        with OTXPulseClient(secret) as client:
            pull_subscription(client, sub(), session)
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == secret

        captured = capsys.readouterr()
        assert secret not in captured.out
        assert secret not in captured.err

    @respx.mock
    def test_key_absent_from_logs_on_error(self, session, capsys):
        secret = "sk-live-secret-key-999"
        respx.get(SEARCH_URL).mock(return_value=httpx.Response(500, text="boom"))

        from scry.ingestion.otx_pulses import pull_all

        results = pull_all(session, api_key=secret, subscriptions=[sub()])
        assert results["ransomware"]["error"] == 1

        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert secret not in combined

    @respx.mock
    def test_key_absent_from_api_response_and_flash(self, capsys):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", PERSONAL_OTX_KEY)
        mock_search([pulse("p1")])

        client = auth_client()
        r = client.post("/ingest/otx-pulses")
        assert PERSONAL_OTX_KEY not in json.dumps(r.json())

        r = client.post(
            "/ui/intel-feeds/otx-pull",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert PERSONAL_OTX_KEY not in flash_of(r)

        captured = capsys.readouterr()
        assert PERSONAL_OTX_KEY not in captured.out
        assert PERSONAL_OTX_KEY not in captured.err


# ------------------------- repo config sanity -------------------------


def test_repo_config_loads():
    """The shipped config/otx_pulses.yaml parses to at least one valid subscription."""
    from scry.ingestion.otx_pulses import load_subscriptions

    subs = load_subscriptions()
    assert subs and all(s.query for s in subs)
