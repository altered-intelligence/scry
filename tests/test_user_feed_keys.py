"""Tests for v0.5.0 step 6: per-user VT/OTX feed keys.

Covers the UserFeedKey model + CRUD (uniqueness, encryption at rest),
the threat-feeds "My API keys" UI (save/test/remove with respx-mocked
outcomes, masked display, key never in responses), key resolution in
POST /enrichment/run (personal vs system vs no-acting-user), the
observable live-lookup verdict panel, bulk "enrich unenriched (my keys)"
with cap + quota guard, the ``scry feeds migrate-env-keys`` CLI, and the
admin enrichment-coverage stats.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE, create_session
from scry.cli import app as cli_app
from scry.config import get_settings
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import Observable, User, UserFeedKey

PASSWORD = "S3cure!pass"
runner = CliRunner()

VT_USER = "https://www.virustotal.com/api/v3/users/current"
OTX_USER = "https://otx.alienvault.com/api/v1/users/me"
VT_IP = "https://www.virustotal.com/api/v3/ip_addresses/{}"
OTX_IP = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_COMMUNITY = "https://api.greynoise.io/v3/community/{}"

VT_KEY = "personal-vt-key-0123"
OTX_KEY = "personal-otx-key-4567"
FG_KEY = "personal-fg-key-89ab"
FG_SEARCH = "https://ioc-api.fortiguard.com/v1/threat_intel_search"
SYS_VT_KEY = "system-vt-key"
SYS_OTX_KEY = "system-otx-key"

TEST_IP = "198.51.100.23"

VT_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 1,
                "harmless": 50,
                "undetected": 10,
            },
            "reputation": -10,
            "tags": ["spam", "ssh"],
            "last_analysis_date": 1714579200,
        }
    }
}

OTX_PAYLOAD = {
    "pulse_info": {"count": 3, "pulses": [{"name": "p1", "tags": ["scanner"], "tlp": "white"}]},
    "reputation": 0,
}


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    """Deterministic system keys + generous rate limits; caches redirected."""
    import scry.enrichment.abuseipdb as aipdb_mod
    import scry.enrichment.greynoise as gn_mod
    import scry.enrichment.otx as otx_mod
    import scry.enrichment.virustotal as vt_mod

    monkeypatch.setattr(vt_mod, "CACHE_DIR", tmp_path / "vt-cache")
    monkeypatch.setattr(otx_mod, "CACHE_DIR", tmp_path / "otx-cache")
    monkeypatch.setattr(aipdb_mod, "CACHE_DIR", tmp_path / "aipdb-cache")
    monkeypatch.setattr(gn_mod, "CACHE_DIR", tmp_path / "gn-cache")
    monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", SYS_VT_KEY)
    monkeypatch.setenv("CTI_OTX_API_KEY", SYS_OTX_KEY)
    monkeypatch.setenv("CTI_ABUSEIPDB_API_KEY", "aipdb-key")
    monkeypatch.setenv("CTI_GREYNOISE_API_KEY", "gn-key")
    monkeypatch.setenv("CTI_VT_RATE_PER_MIN", "1000")
    monkeypatch.setenv("CTI_VT_DAILY_QUOTA", "1000")
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
    """A TestClient with a signed-in session cookie for ``username``."""
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


def seed_ip(value: str = TEST_IP, **kwargs) -> int:
    with session_scope() as s:
        ob = Observable(type="ipv4", value=value, normalized_value=value, **kwargs)
        s.add(ob)
        s.flush()
        return ob.id


def feed_key_row(provider: str) -> UserFeedKey | None:
    with session_scope() as s:
        return s.scalar(select(UserFeedKey).where(UserFeedKey.provider == provider))


# ------------------------- model + CRUD -------------------------


class TestUserFeedKeyCrud:
    def test_set_get_roundtrip_encrypted(self):
        from scry.crypto import decrypt
        from scry.enrichment.user_keys import get_decrypted_key, get_key, set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
            s.commit()
            row = get_key(s, uid, "virustotal")
            assert row is not None
            assert row.api_key_encrypted != VT_KEY
            assert VT_KEY not in row.api_key_encrypted
            assert decrypt(row.api_key_encrypted) == VT_KEY
            assert get_decrypted_key(s, uid, "virustotal") == VT_KEY
            assert get_decrypted_key(s, uid, "otx") == ""

    def test_set_key_is_upsert_one_row_per_user_provider(self):
        from scry.enrichment.user_keys import get_decrypted_key, set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", "first-key")
            set_key(s, uid, "virustotal", VT_KEY)
            set_key(s, uid, "otx", OTX_KEY)
            s.commit()
            rows = s.scalars(select(UserFeedKey).where(UserFeedKey.user_id == uid)).all()
            assert len(rows) == 2
            assert s.scalar(select(func.count(UserFeedKey.id))) == 2
            assert get_decrypted_key(s, uid, "virustotal") == VT_KEY

    def test_invalid_provider_and_empty_key_rejected(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            with pytest.raises(ValueError, match="Unknown personal-key provider"):
                set_key(s, uid, "abuseipdb", "nope")
            with pytest.raises(ValueError, match="must not be empty"):
                set_key(s, uid, "virustotal", "   ")

    def test_delete_key(self):
        from scry.enrichment.user_keys import delete_key, get_key, set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
            s.commit()
            assert delete_key(s, uid, "virustotal") is True
            assert delete_key(s, uid, "virustotal") is False
            assert get_key(s, uid, "virustotal") is None

    def test_cascade_delete_with_user(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
            s.commit()
        with session_scope() as s:
            s.delete(s.get(User, uid))
            s.commit()
        with session_scope() as s:
            assert s.scalars(select(UserFeedKey)).all() == []

    def test_keys_for_user(self):
        from scry.enrichment.user_keys import keys_for_user, set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
            s.commit()
            assert keys_for_user(s, uid) == {"virustotal": VT_KEY}

    def test_record_test_result(self):
        from scry.enrichment.user_keys import get_key, record_test_result, set_key

        uid = make_user()
        with session_scope() as s:
            row = set_key(s, uid, "otx", OTX_KEY)
            record_test_result(s, row, ok=False, error="HTTP 401: key rejected")
            s.commit()
            row = get_key(s, uid, "otx")
            assert row.last_test_ok is False
            assert row.last_test_error == "HTTP 401: key rejected"
            assert row.last_test_at is not None


# ------------------------- test_key() sanitization -------------------------


class TestTestKey:
    @respx.mock
    def test_vt_ok(self):
        from scry.enrichment.user_keys import test_key

        route = respx.get(VT_USER).mock(return_value=httpx.Response(200, json={"data": {}}))
        ok, error = test_key("virustotal", VT_KEY)
        assert ok and error == ""
        assert route.called
        assert route.calls[0].request.headers["x-apikey"] == VT_KEY

    @respx.mock
    def test_otx_ok(self):
        from scry.enrichment.user_keys import test_key

        route = respx.get(OTX_USER).mock(return_value=httpx.Response(200, json={}))
        ok, error = test_key("otx", OTX_KEY)
        assert ok and error == ""
        assert route.calls[0].request.headers["X-OTX-API-KEY"] == OTX_KEY

    @respx.mock
    def test_fortiguard_ok_found_and_not_found(self):
        """FortiGuard has no whoami: 200 (found) and 404 (auth OK, unknown
        indicator) both count as Connected; 401/403/429 fail."""
        from scry.enrichment.user_keys import test_key

        route = respx.get(FG_SEARCH).mock(return_value=httpx.Response(200, json={"wf_cate": "Botnet"}))
        ok, error = test_key("fortiguard", FG_KEY)
        assert ok and error == ""
        assert route.calls[0].request.headers["api_key"] == FG_KEY
        assert route.calls[0].request.url.params["indicator"] == "94.100.18.64"

        route.mock(return_value=httpx.Response(404))
        ok, error = test_key("fortiguard", FG_KEY)
        assert ok and error == ""

    @respx.mock
    @pytest.mark.parametrize("status", [401, 403, 429])
    def test_fortiguard_failures(self, status):
        from scry.enrichment.user_keys import test_key

        respx.get(FG_SEARCH).mock(return_value=httpx.Response(status))
        ok, error = test_key("fortiguard", FG_KEY)
        assert not ok
        assert f"HTTP {status}" in error
        assert FG_KEY not in error

    @respx.mock
    @pytest.mark.parametrize("status", [401, 403, 500])
    def test_failures_report_status_not_key(self, status):
        from scry.enrichment.user_keys import test_key

        respx.get(VT_USER).mock(return_value=httpx.Response(status))
        ok, error = test_key("virustotal", VT_KEY)
        assert not ok
        assert f"HTTP {status}" in error
        assert VT_KEY not in error

    @respx.mock
    def test_network_error_sanitized(self):
        from scry.enrichment.user_keys import test_key

        respx.get(VT_USER).mock(side_effect=httpx.ConnectError("refused"))
        ok, error = test_key("virustotal", VT_KEY)
        assert not ok
        assert VT_KEY not in error


# ------------------------- My API keys UI -------------------------


class TestMyKeysUi:
    def test_page_shows_my_keys_section(self):
        make_user()
        client = auth_client()
        r = client.get("/ui/intel-feeds/threat-feeds")
        assert r.status_code == 200
        assert "My API keys" in r.text
        assert "VirusTotal" in r.text
        assert "AlienVault OTX" in r.text
        assert "FortiGuard" in r.text

    def test_saved_key_masked_in_page(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        client = auth_client()
        r = client.get("/ui/intel-feeds/threat-feeds")
        assert VT_KEY[-4:] in r.text  # mask keeps the last 4 chars
        assert VT_KEY not in r.text  # full key never rendered

    def test_save_flow(self):
        make_user()
        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/my-keys/virustotal/save",
            data={"csrf": csrf_for(client), "api_key": VT_KEY},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "saved" in flash_of(r)
        row = feed_key_row("virustotal")
        assert row is not None and row.api_key_encrypted != VT_KEY

    def test_save_rejects_bad_csrf_and_empty_key(self):
        make_user()
        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/my-keys/virustotal/save",
            data={"csrf": "bogus", "api_key": VT_KEY},
            follow_redirects=False,
        )
        assert "CSRF" in flash_of(r)
        r = client.post(
            "/ui/intel-feeds/my-keys/virustotal/save",
            data={"csrf": csrf_for(client), "api_key": "  "},
            follow_redirects=False,
        )
        assert "must not be empty" in flash_of(r)

    @respx.mock
    def test_successful_test_marks_connected(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        client = auth_client()
        route = respx.get(VT_USER).mock(return_value=httpx.Response(200, json={"data": {}}))
        r = client.post(
            "/ui/intel-feeds/my-keys/virustotal/test",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "Connected" in flash_of(r)
        assert route.called
        assert route.calls[0].request.headers["x-apikey"] == VT_KEY
        row = feed_key_row("virustotal")
        assert row.last_test_ok is True
        assert row.last_test_error is None
        assert row.last_test_at is not None

    @respx.mock
    def test_failed_test_marks_failed_without_leaking_key(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", OTX_KEY)
        client = auth_client()
        respx.get(OTX_USER).mock(return_value=httpx.Response(401))
        r = client.post(
            "/ui/intel-feeds/my-keys/otx/test",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        flash = flash_of(r)
        assert "test failed" in flash and "HTTP 401" in flash
        assert OTX_KEY not in flash
        row = feed_key_row("otx")
        assert row.last_test_ok is False
        assert OTX_KEY not in (row.last_test_error or "")

    def test_page_renders_failed_badge_and_error(self):
        from scry.enrichment.user_keys import record_test_result, set_key

        uid = make_user()
        with session_scope() as s:
            row = set_key(s, uid, "virustotal", VT_KEY)
            record_test_result(s, row, ok=False, error="HTTP 401: key rejected")
        client = auth_client()
        r = client.get("/ui/intel-feeds/threat-feeds")
        assert "Failed (HTTP 401: key rejected)" in r.text
        assert VT_KEY not in r.text

    def test_remove_flow(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        client = auth_client()
        r = client.post(
            "/ui/intel-feeds/my-keys/virustotal/remove",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert "removed" in flash_of(r)
        with session_scope() as s:
            assert s.scalars(select(UserFeedKey)).all() == []

    def test_anonymous_save_redirects_to_login(self):
        make_user()  # users exist → UI gated
        client = TestClient(app)
        r = client.post(
            "/ui/intel-feeds/my-keys/virustotal/save",
            data={"api_key": VT_KEY},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login")


# ------------------------- /enrichment/run key resolution -------------------------


def _mock_system_ip_providers() -> tuple:
    """respx mocks for the system-key IP providers (AbuseIPDB, GreyNoise)."""
    abuseipdb = respx.get(ABUSEIPDB_CHECK).mock(
        return_value=httpx.Response(
            200, json={"data": {"ipAddress": TEST_IP, "abuseConfidenceScore": 10, "countryCode": "US"}}
        )
    )
    greynoise = respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
        return_value=httpx.Response(200, json={"ip": TEST_IP, "noise": False, "riot": False})
    )
    return abuseipdb, greynoise


class TestEnrichmentRunKeyResolution:
    @respx.mock
    def test_user_with_vt_key_only_runs_vt_with_personal_key(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        seed_ip()
        abuseipdb_route, greynoise_route = _mock_system_ip_providers()
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))
        otx_route = respx.get(OTX_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=OTX_PAYLOAD))

        client = auth_client()
        r = client.post("/enrichment/run")
        assert r.status_code == 200
        body = r.json()
        assert body["vt_enriched"] == 1
        assert body["skipped"]["otx"] == "no personal key"
        assert "otx_enriched" not in body
        # VT ran with the ACTING USER's personal key, not the system key
        assert vt_route.calls[0].request.headers["x-apikey"] == VT_KEY
        assert not otx_route.called
        # IP providers have no per-user keys → system chain still applies
        assert abuseipdb_route.called
        assert greynoise_route.called
        assert body["abuseipdb_enriched"] == 1
        assert body["greynoise_enriched"] == 1

    @respx.mock
    def test_user_with_no_keys_skips_vt_otx_but_system_providers_run(self):
        make_user()
        seed_ip()
        abuseipdb_route, greynoise_route = _mock_system_ip_providers()
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))
        otx_route = respx.get(OTX_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=OTX_PAYLOAD))

        client = auth_client()
        r = client.post("/enrichment/run")
        assert r.status_code == 200
        body = r.json()
        assert body["skipped"]["virustotal"] == "no personal key"
        assert body["skipped"]["otx"] == "no personal key"
        assert not vt_route.called
        assert not otx_route.called
        assert abuseipdb_route.called
        assert greynoise_route.called

    @respx.mock
    def test_no_acting_user_keeps_system_path(self, monkeypatch):
        """Zero users → legacy open API; the system env key chain decides."""
        assert session_scalar_user_count() == 0
        seed_ip()
        monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", "")
        get_settings.cache_clear()
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        client = TestClient(app)
        r = client.post("/enrichment/run", params=[("providers", "virustotal")])
        assert r.status_code == 200
        # empty system key → skipped, exactly the pre-step-6 behavior
        assert r.json()["skipped"] == {"virustotal": "no api key"}
        assert not vt_route.called

    @respx.mock
    def test_providers_filter_still_applies_in_user_mode(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        seed_ip()
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        client = auth_client()
        r = client.post("/enrichment/run", params=[("providers", "virustotal")])
        body = r.json()
        assert body["vt_enriched"] == 1
        assert body["providers"] == ["virustotal"]
        assert vt_route.calls[0].request.headers["x-apikey"] == VT_KEY

        r = client.post("/enrichment/run", params=[("providers", "nonsense")])
        assert r.status_code == 400


def session_scalar_user_count() -> int:
    with session_scope() as s:
        return s.scalar(select(func.count(User.id)))


# ------------------------- live lookup -------------------------


class TestLiveLookup:
    @respx.mock
    def test_lookup_with_personal_key_renders_verdict_panel(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        ob_id = seed_ip()
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        client = auth_client()
        r = client.post(
            f"/ui/observables/{ob_id}/lookup/virustotal",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "live lookup complete" in flash_of(r)
        assert vt_route.calls[0].request.headers["x-apikey"] == VT_KEY

        detail = client.get(f"/ui/observables/{ob_id}")
        assert detail.status_code == 200
        assert "VirusTotal verdict" in detail.text
        assert '<span class="badge bad">malicious 12</span>' in detail.text
        assert "last analysis" in detail.text
        # the result landed in the SHARED enrichment
        with session_scope() as s:
            ob = s.get(Observable, ob_id)
            assert (ob.enrichment or {}).get("virustotal", {}).get("malicious") == 12
            assert "virustotal_checked_at" in (ob.enrichment or {})

    @respx.mock
    def test_lookup_otx_panel(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "otx", OTX_KEY)
        ob_id = seed_ip()
        otx_route = respx.get(OTX_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=OTX_PAYLOAD))

        client = auth_client()
        r = client.post(
            f"/ui/observables/{ob_id}/lookup/otx",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert otx_route.calls[0].request.headers["X-OTX-API-KEY"] == OTX_KEY
        detail = client.get(f"/ui/observables/{ob_id}")
        assert "OTX verdict" in detail.text
        assert "pulse count" in detail.text

    @respx.mock
    def test_lookup_unknown_observable_404(self):
        make_user()
        client = auth_client()
        r = client.post(
            "/ui/observables/999/lookup/virustotal",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert r.status_code == 404

    @respx.mock
    def test_lookup_quota_error_is_distinct(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        ob_id = seed_ip()
        respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(429))

        client = auth_client()
        r = client.post(
            f"/ui/observables/{ob_id}/lookup/virustotal",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        flash = flash_of(r)
        assert "quota/rate limit" in flash
        assert VT_KEY not in flash

    def test_lookup_button_hidden_without_personal_key(self):
        make_user()
        ob_id = seed_ip()
        client = auth_client()
        detail = client.get(f"/ui/observables/{ob_id}")
        assert "Live lookup" not in detail.text
        r = client.post(
            f"/ui/observables/{ob_id}/lookup/virustotal",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert "No personal" in flash_of(r)

    def test_lookup_requires_login(self):
        make_user()
        ob_id = seed_ip()
        client = TestClient(app)
        r = client.post(f"/ui/observables/{ob_id}/lookup/virustotal", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login")


# ------------------------- bulk enrich unenriched -------------------------


class TestEnrichUnenriched:
    def _seed_many(self, n: int) -> None:
        with session_scope() as s:
            for i in range(n):
                value = f"198.51.100.{i + 1}"
                s.add(Observable(type="ipv4", value=value, normalized_value=value))
            s.flush()

    @respx.mock
    def test_cap_of_50_per_run(self, monkeypatch):
        from scry.enrichment.user_keys import set_key

        # VT-only run: empty the system IP-provider keys
        monkeypatch.setenv("CTI_ABUSEIPDB_API_KEY", "")
        monkeypatch.setenv("CTI_GREYNOISE_API_KEY", "")
        get_settings.cache_clear()
        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        self._seed_many(60)
        first_route = respx.get(VT_IP.format("198.51.100.1")).mock(
            return_value=httpx.Response(200, json=VT_PAYLOAD)
        )
        for i in range(2, 61):
            respx.get(VT_IP.format(f"198.51.100.{i}")).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        client = auth_client()
        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        flash = flash_of(r)
        assert "checked 50" in flash
        assert "virustotal enriched 50" in flash
        assert first_route.called

    @respx.mock
    def test_quota_guard_limits_network_calls(self, monkeypatch):
        from scry.enrichment.user_keys import set_key

        monkeypatch.setenv("CTI_ABUSEIPDB_API_KEY", "")
        monkeypatch.setenv("CTI_GREYNOISE_API_KEY", "")
        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        self._seed_many(5)
        monkeypatch.setenv("CTI_VT_DAILY_QUOTA", "2")
        get_settings.cache_clear()
        vt_route = respx.get(re.compile(r"virustotal\.com")).mock(
            return_value=httpx.Response(200, json=VT_PAYLOAD)
        )

        client = auth_client()
        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        flash = flash_of(r)
        assert "skipped per quota: virustotal" in flash
        assert vt_route.call_count == 2  # quota stops the network long before 5

    @respx.mock
    def test_without_personal_keys_rejected(self):
        make_user()
        self._seed_many(3)
        client = auth_client()
        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert "No personal VT/OTX keys" in flash_of(r)

    def test_button_visibility_and_enriched_badges(self):
        from scry.enrichment.user_keys import set_key

        uid = make_user()
        with session_scope() as s:
            set_key(s, uid, "virustotal", VT_KEY)
        seed_ip(
            enrichment={
                "virustotal_checked_at": "2024-01-01T00:00:00+00:00",
                "virustotal": {"malicious": 4, "suspicious": 0, "undetected": 3},
            }
        )
        client = auth_client()
        r = client.get("/ui/observables")
        assert "Enrich unenriched (my keys)" in r.text
        assert "✓ 4" in r.text  # enriched badge coloured by malicious verdict

        # a user without keys doesn't see the button
        make_user("bob")
        client_b = auth_client("bob")
        r = client_b.get("/ui/observables")
        assert "Enrich unenriched (my keys)" not in r.text


# ------------------------- migrate-env-keys CLI -------------------------


class TestMigrateEnvKeys:
    def _seed_users(self):
        make_user("alakhani", role="admin")
        make_user("admin", role="admin")

    def test_migrates_env_keys_for_both_users(self, monkeypatch):
        self._seed_users()
        monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", "env-vt-key-9")
        monkeypatch.setenv("CTI_OTX_API_KEY", "env-otx-key-8")
        get_settings.cache_clear()

        from scry.crypto import decrypt
        from scry.enrichment.user_keys import get_key

        result = runner.invoke(cli_app, ["feeds", "migrate-env-keys", "--users", "alakhani,admin"])
        assert result.exit_code == 0, result.output
        assert "4 migrated" in result.output  # 2 users x 2 providers
        assert "env-vt-key-9" not in result.output
        assert "env-otx-key-8" not in result.output
        with session_scope() as s:
            for username in ("alakhani", "admin"):
                user = s.scalar(select(User).where(User.username == username))
                vt = get_key(s, user.id, "virustotal")
                otx = get_key(s, user.id, "otx")
                assert decrypt(vt.api_key_encrypted) == "env-vt-key-9"
                assert decrypt(otx.api_key_encrypted) == "env-otx-key-8"

    def test_skips_existing_unknown_users_and_empty_env(self, monkeypatch):
        from scry.enrichment.user_keys import get_decrypted_key, set_key

        self._seed_users()
        with session_scope() as s:
            alakhani = s.scalar(select(User).where(User.username == "alakhani"))
            set_key(s, alakhani.id, "virustotal", "already-there")
        monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", "env-vt-key-9")
        monkeypatch.setenv("CTI_OTX_API_KEY", "")
        get_settings.cache_clear()

        result = runner.invoke(cli_app, ["feeds", "migrate-env-keys", "--users", "alakhani,admin,nobody"])
        assert result.exit_code == 0, result.output
        assert "1 migrated" in result.output
        assert "already had keys" in result.output
        assert "no such user" in result.output
        with session_scope() as s:
            admin_user = s.scalar(select(User).where(User.username == "admin"))
            # admin had no keys: VT migrated from env, OTX env empty → skipped
            assert get_decrypted_key(s, admin_user.id, "virustotal") == "env-vt-key-9"
            assert get_decrypted_key(s, admin_user.id, "otx") == ""
            # alakhani already had a VT personal key → untouched
            alakhani = s.scalar(select(User).where(User.username == "alakhani"))
            assert get_decrypted_key(s, alakhani.id, "virustotal") == "already-there"

    def test_empty_env_keys_skip_everything(self, monkeypatch):
        self._seed_users()
        monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", "")
        monkeypatch.setenv("CTI_OTX_API_KEY", "")
        get_settings.cache_clear()

        result = runner.invoke(cli_app, ["feeds", "migrate-env-keys", "--users", "alakhani"])
        assert result.exit_code == 0, result.output
        assert "0 migrated" in result.output
        with session_scope() as s:
            assert s.scalar(select(func.count(UserFeedKey.id))) == 0


# ------------------------- admin coverage stats -------------------------


class TestAdminCoverage:
    def test_coverage_panel_and_quota(self):
        make_user("root", role="admin")
        seed_ip(
            "198.51.100.7",
            enrichment={
                "virustotal_checked_at": "2024-01-01T00:00:00+00:00",
                "virustotal": {"malicious": 5, "suspicious": 0, "undetected": 2},
                "otx_checked_at": "2024-01-01T00:00:00+00:00",
                "otx": {"pulse_count": 0},
            },
        )
        seed_ip(
            "198.51.100.8",
            enrichment={
                "otx_checked_at": "2024-01-02T00:00:00+00:00",
                "otx": {"pulse_count": 7},
            },
        )
        client = auth_client("root")
        r = client.get("/admin")
        assert r.status_code == 200
        assert "Enrichment coverage" in r.text
        assert "VirusTotal daily quota" in r.text
        # VT: 1 checked / 1 malicious; OTX: 2 checked / 1 malicious verdict
        assert r.text.count('<span class="badge bad">1</span>') >= 2

    def test_coverage_quota_snapshot(self):
        import json

        from scry.models import SystemSetting

        make_user("root", role="admin")
        with session_scope() as s:
            s.add(
                SystemSetting(
                    key="enrichment.vt_daily_quota",
                    value=json.dumps({"date": datetime.now(UTC).date().isoformat(), "used": 30}),
                )
            )
        client = auth_client("root")
        r = client.get("/admin")
        assert "30" in r.text
        assert "970" in r.text  # 1000 - 30 remaining
