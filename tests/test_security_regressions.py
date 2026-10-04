"""Regression tests for the security-review fixes.

Covers: method-aware API auth exemptions (PUT /api/ai/provider), admin
gating of provider configuration, the stored-key/base_url change guard,
redirect-hop SSRF re-validation, DNS fail-closed, the streamed fetch byte
cap, CSRF guards on the three UI POSTs, the search.html model escaping,
and the PATCH /sources field allowlist.
"""

from __future__ import annotations

import gzip
import socket
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import scry.ingestion.ssrf as ssrf_mod
from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE
from scry.config import get_settings
from scry.db import session_scope
from scry.ingestion.fetcher import SafeFetcher
from scry.ingestion.policy import PolicyDecision
from scry.main import _admin_csrf_token, app
from scry.models import LLMSetting, Source, User

PASSWORD = "S3cure!pass"
MASTER_KEY = "test-master-key"

_POLICY = PolicyDecision(
    allowed=True,
    fetch_mode="text",
    allow_javascript=False,
    allow_file_download=False,
    allow_binary_download=False,
    respect_robots_txt=False,
    max_depth=1,
    requires_analyst_approval=False,
    safety_mode=None,
)

# Public IP literal — evaluate_url accepts it without any DNS lookup
# (getaddrinfo on a numeric host never touches the network).
_PUBLIC_URL = "http://93.184.216.34/feed"


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


def logged_in_client(username: str) -> TestClient:
    client = TestClient(app)
    client.post("/login", data={"username": username, "password": PASSWORD})
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


# ------------------------- 1. method-aware API auth exemptions -------------------------


@pytest.fixture
def master_key(monkeypatch):
    monkeypatch.setenv("CTI_API_KEY", MASTER_KEY)
    get_settings.cache_clear()
    yield MASTER_KEY
    get_settings.cache_clear()


class TestMethodAwareExemptions:
    def test_provider_list_needs_auth_but_status_stays_open(self, master_key):
        with TestClient(app) as client:
            assert client.get("/api/ai/provider").status_code == 401
            assert client.get("/api/ai/provider", headers={"X-API-Key": master_key}).status_code == 200
            assert client.get("/api/ai/status").status_code == 200

    def test_put_provider_requires_auth(self, master_key):
        """The leak: PUT used to ride the GET exemption and configure providers
        (incl. base_url) anonymously."""
        with TestClient(app) as client:
            r = client.put("/api/ai/provider", json={"provider": "openai", "api_key": "sk-x"})
            assert r.status_code == 401

    def test_master_key_can_still_configure(self, master_key):
        with TestClient(app) as client:
            r = client.put(
                "/api/ai/provider",
                json={"provider": "bogus"},
                headers={"X-API-Key": master_key},
            )
            assert r.status_code == 404  # passed auth, unknown provider


class TestProviderAdminGate:
    def test_non_admin_user_gets_403(self):
        make_user("bob")
        client = logged_in_client("bob")
        r = client.put("/api/ai/provider", json={"provider": "bogus"})
        assert r.status_code == 403

    def test_admin_user_allowed(self):
        make_user("root", role="admin")
        client = logged_in_client("root")
        r = client.put("/api/ai/provider", json={"provider": "bogus"})
        assert r.status_code == 404  # passed the admin gate, unknown provider


class TestBaseUrlKeyGuard:
    """Changing base_url must require re-entering the API key, so the stored
    (decrypted) key is never POSTed to a new, attacker-chosen endpoint."""

    def _put(self, client: TestClient, **payload):
        return client.put("/api/ai/provider", json=payload)

    def test_base_url_change_without_key_rejected(self):
        with TestClient(app) as client:
            r = self._put(client, provider="openai", api_key="sk-stored", base_url="https://api.openai.com")
            assert r.status_code == 200
            # Silent endpoint swap, key kept → refused.
            r = self._put(client, provider="openai", base_url="https://attacker.example.com")
            assert r.status_code == 400
            assert "Re-enter the API key" in r.json()["detail"]
            # The stored base_url was NOT changed.
            with session_scope() as s:
                row = s.query(LLMSetting).filter_by(provider="openai").one()
                assert row.base_url == "https://api.openai.com"

    def test_base_url_change_with_key_allowed(self):
        with TestClient(app) as client:
            self._put(client, provider="openai", api_key="sk-stored", base_url="https://api.openai.com")
            r = self._put(
                client, provider="openai", api_key="sk-new", base_url="https://attacker.example.com"
            )
            assert r.status_code == 200

    def test_same_base_url_without_key_allowed(self):
        with TestClient(app) as client:
            self._put(client, provider="openai", api_key="sk-stored", base_url="https://api.openai.com")
            # Re-saving with the unchanged base_url (what the UI sends) is fine.
            r = self._put(client, provider="openai", base_url="https://api.openai.com")
            assert r.status_code == 200


# ------------------------- 3/4. SSRF: redirect hops + DNS fail-closed -------------------------


@respx.mock
async def test_redirect_to_link_local_refused():
    """A feed that 302s to the cloud metadata address must be refused BEFORE
    the redirect target is requested."""
    respx.get(_PUBLIC_URL).mock(
        return_value=httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
    )
    meta = respx.get("http://169.254.169.254/latest/meta-data").mock(
        return_value=httpx.Response(200, text="secret")
    )
    async with SafeFetcher() as f:
        result = await f.fetch(_PUBLIC_URL, policy=_POLICY)
    assert result.error is not None
    assert "ssrf blocked" in result.error
    assert meta.call_count == 0  # never requested


@respx.mock
async def test_redirect_to_public_url_followed():
    respx.get(_PUBLIC_URL).mock(
        return_value=httpx.Response(302, headers={"location": "http://93.184.216.34/real-feed"})
    )
    respx.get("http://93.184.216.34/real-feed").mock(
        return_value=httpx.Response(
            200, text="<rss>ok</rss>", headers={"content-type": "application/rss+xml"}
        )
    )
    async with SafeFetcher() as f:
        result = await f.fetch(_PUBLIC_URL, policy=_POLICY)
    assert result.error is None
    assert result.status_code == 200
    assert "ok" in result.text


def test_unresolvable_host_fails_closed(monkeypatch):
    def _boom(host, *args, **kwargs):
        raise socket.gaierror(f"name resolution failed for {host}")

    monkeypatch.setattr(ssrf_mod.socket, "getaddrinfo", _boom)
    res = ssrf_mod.evaluate_url("http://unresolvable-host.example/feed")
    assert not res.allowed
    assert "resolution failed" in res.reason


# ------------------------- 9. streamed byte cap -------------------------


@pytest.fixture
def tiny_cap(monkeypatch):
    monkeypatch.setenv("CTI_MAX_FETCH_BYTES", "1024")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@respx.mock
async def test_plain_body_over_cap_refused(tiny_cap):
    body = b"x" * 5000  # no Content-Length header → early gate can't help
    respx.get(_PUBLIC_URL).mock(
        return_value=httpx.Response(200, content=body, headers={"content-type": "text/plain"})
    )
    async with SafeFetcher() as f:
        result = await f.fetch(_PUBLIC_URL, policy=_POLICY)
    assert result.status_code == 200
    assert "too large" in result.error
    assert result.content == b""


@respx.mock
async def test_gzip_bomb_capped_on_decompressed_stream(tiny_cap):
    """A tiny gzipped response decompressing past the cap is refused — the
    cap is enforced while streaming, never after buffering it whole."""
    big = b"A" * (512 * 1024)
    compressed = gzip.compress(big)
    assert len(compressed) < 1024  # the wire size alone would pass the old check
    respx.get(_PUBLIC_URL).mock(
        return_value=httpx.Response(
            200,
            content=compressed,
            headers={"content-type": "text/plain", "content-encoding": "gzip"},
        )
    )
    async with SafeFetcher() as f:
        result = await f.fetch(_PUBLIC_URL, policy=_POLICY)
    assert "too large" in result.error
    assert result.content == b""


# ------------------------- 2. search.html model escaping -------------------------


def test_search_template_escapes_model():
    template = (Path(__file__).parent.parent / "scry" / "ui" / "templates" / "search.html").read_text()
    # The model label is interpolated into innerHTML — it must go through esc()
    # like every sibling value.
    assert "esc(res.data.model)" in template


# ------------------------- 7. CSRF on the three UI POSTs -------------------------


class TestUiCsrfGuards:
    def test_ingest_run_rejects_missing_token(self):
        make_user("analyst")
        client = logged_in_client("analyst")
        r = client.post("/ui/ingest/run", data={}, follow_redirects=False)
        assert r.status_code in (303, 403)
        if r.status_code == 303:
            assert "CSRF" in r.headers["location"]

    def test_reviews_bulk_rejects_missing_token(self):
        make_user("analyst")
        with session_scope() as s:
            from scry.models import AnalystReview

            row = AnalystReview(item_type="observable", item_id=1, reason="t", status="open")
            s.add(row)
            s.flush()
            rid = row.id
        client = logged_in_client("analyst")
        r = client.post(
            "/ui/reviews/bulk",
            data={"review_ids": [str(rid)], "action": "approve"},
            follow_redirects=False,
        )
        assert r.status_code in (303, 403)
        if r.status_code == 303:
            assert "CSRF" in r.headers["location"]
        with session_scope() as s:
            from scry.models import AnalystReview

            assert s.get(AnalystReview, rid).status == "open"  # unchanged

    def test_review_detail_rejects_missing_token(self):
        make_user("analyst")
        with session_scope() as s:
            from scry.models import AnalystReview

            row = AnalystReview(item_type="observable", item_id=1, reason="t", status="open")
            s.add(row)
            s.flush()
            rid = row.id
        client = logged_in_client("analyst")
        r = client.post(
            f"/ui/reviews/{rid}",
            data={"status": "closed"},
            follow_redirects=False,
        )
        assert r.status_code in (303, 403)
        if r.status_code == 303:
            assert "CSRF" in r.headers["location"]
        with session_scope() as s:
            from scry.models import AnalystReview

            assert s.get(AnalystReview, rid).status == "open"  # unchanged

    def test_valid_token_accepted(self):
        make_user("analyst")
        with session_scope() as s:
            from scry.models import AnalystReview

            row = AnalystReview(item_type="observable", item_id=1, reason="t", status="open")
            s.add(row)
            s.flush()
            rid = row.id
        client = logged_in_client("analyst")
        r = client.post(
            "/ui/reviews/bulk",
            data={"csrf": csrf_for(client), "review_ids": [str(rid)], "action": "approve"},
            follow_redirects=False,
        )
        assert "1+reviews+approved" in r.headers["location"]


# ------------------------- 6. PATCH /sources allowlist -------------------------


class TestSourcePatchAllowlist:
    def _source(self) -> int:
        with session_scope() as s:
            src = Source(
                name="Patch Me",
                type="vendor_blog",
                url="https://example.com",
                enabled=True,
                collection_policy="safe_public_web",
            )
            s.add(src)
            s.commit()
            return src.id

    def test_allowed_fields_update(self):
        sid = self._source()
        with TestClient(app) as client:
            r = client.patch(f"/sources/{sid}", json={"name": "Renamed", "enabled": False})
            assert r.status_code == 200
            body = r.json()
            assert body["name"] == "Renamed"
            assert body["enabled"] is False

    def test_id_and_unknown_fields_ignored(self):
        sid = self._source()
        with TestClient(app) as client:
            r = client.patch(
                f"/sources/{sid}",
                json={"id": 99999, "created_at": "x", "not_a_column": True, "name": "Still Renamed"},
            )
            assert r.status_code == 200
        with session_scope() as s:
            src = s.get(Source, sid)
            assert src is not None  # id unchanged (row not hijacked)
            assert src.name == "Still Renamed"
            assert not hasattr(src, "not_a_column")
            assert s.get(Source, 99999) is None
