"""Security hardening: Secure auth cookies, provider-list auth, admin-only source creation."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE
from scry.auth.totp import MFA_PENDING_COOKIE
from scry.config import get_settings
from scry.crypto import encrypt
from scry.db import session_scope
from scry.main import app
from scry.models import Source, User

PASSWORD = "S3cure!pass"
SOURCE = {
    "name": "Injected Feed",
    "type": "vendor_blog",
    "url": "https://example.com/blog",
    "feed": "https://example.com/feed",
    "enabled": True,
    "priority": "high",
    "baseline_confidence": 95,
    "collection_policy": "safe_public_web",
    "independent": True,
    "rate_limit_per_minute": 10,
    "tags": [],
}


def make_user(username="alice", role="user", **extra):
    with session_scope() as s:
        s.add(
            User(
                username=username,
                email=f"{username}@example.com",
                role=role,
                password_hash=hash_password(PASSWORD),
                **extra,
            )
        )


def login(client, username="alice"):
    return client.post("/login", data={"username": username, "password": PASSWORD}, follow_redirects=False)


def set_cookie_header(response, name):
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{name}="):
            return header
    raise AssertionError(f"no Set-Cookie for {name}: {response.headers.get_list('set-cookie')}")


def secure_flag(header: str) -> bool:
    return "secure" in [part.strip().lower() for part in header.split(";")]


@pytest.fixture
def cookie_mode(monkeypatch):
    def _set(value):
        monkeypatch.setenv("CTI_COOKIE_SECURE", value)
        get_settings.cache_clear()

    yield _set
    get_settings.cache_clear()


class TestSecureCookies:
    def test_auto_http_has_no_secure_flag_and_keeps_other_attributes(self, cookie_mode):
        cookie_mode("auto")
        make_user()
        header = set_cookie_header(login(TestClient(app)), SESSION_COOKIE)
        assert not secure_flag(header)
        assert "httponly" in header.lower() and "samesite=lax" in header.lower()

    def test_auto_https_marks_session_cookie_secure(self, cookie_mode):
        cookie_mode("auto")
        make_user()
        client = TestClient(app, base_url="https://testserver")
        header = set_cookie_header(login(client), SESSION_COOKIE)
        assert secure_flag(header) and "httponly" in header.lower()

    def test_forced_on_over_plain_http(self, cookie_mode):
        cookie_mode("true")
        make_user()
        assert secure_flag(set_cookie_header(login(TestClient(app)), SESSION_COOKIE))

    def test_forced_off_over_https(self, cookie_mode):
        cookie_mode("false")
        make_user()
        client = TestClient(app, base_url="https://testserver")
        assert not secure_flag(set_cookie_header(login(client), SESSION_COOKIE))

    def test_mfa_pending_cookie_is_secure_too(self, cookie_mode):
        cookie_mode("auto")
        make_user(totp_enabled=True, totp_secret_encrypted=encrypt("JBSWY3DPEHPK3PXP"))
        client = TestClient(app, base_url="https://testserver")
        r = login(client)
        assert r.headers["location"].startswith("/login/mfa")
        assert secure_flag(set_cookie_header(r, MFA_PENDING_COOKIE))

    def test_setup_csrf_cookie_is_secure_over_https(self, cookie_mode, monkeypatch):
        cookie_mode("auto")
        monkeypatch.setenv("CTI_OPEN_ACCESS", "false")
        get_settings.cache_clear()
        with TestClient(app, base_url="https://testserver") as client:
            assert secure_flag(set_cookie_header(client.get("/setup"), "scry_setup_csrf"))

    def test_setup_session_cookie_is_secure_over_https(self, cookie_mode, monkeypatch):
        cookie_mode("auto")
        monkeypatch.setenv("CTI_OPEN_ACCESS", "false")
        get_settings.cache_clear()
        with TestClient(app, base_url="https://testserver") as client:
            token = re.search(r'name="csrf" value="([^"]+)"', client.get("/setup").text).group(1)
            r = client.post(
                "/setup",
                data={"csrf": token, "username": "root", "password": PASSWORD, "confirm_password": PASSWORD},
                follow_redirects=False,
            )
            assert secure_flag(set_cookie_header(r, SESSION_COOKIE))


class TestProviderListAuth:
    def test_requires_auth_once_users_exist(self):
        make_user()
        with TestClient(app) as client:
            assert client.get("/api/ai/provider").status_code == 401
            assert client.get("/api/ai/status").status_code == 200  # monitoring probe stays open

    def test_session_cookie_still_works_for_the_search_page(self):
        make_user()
        client = TestClient(app)
        login(client)
        r = client.get("/api/ai/provider")
        assert r.status_code == 200 and "providers" in r.json()

    def test_master_key_works_and_no_key_is_rejected(self, monkeypatch):
        monkeypatch.setenv("CTI_API_KEY", "mk-test")
        get_settings.cache_clear()
        with TestClient(app) as client:
            assert client.get("/api/ai/provider").status_code == 401
            assert client.get("/api/ai/provider", headers={"X-API-Key": "mk-test"}).status_code == 200
        get_settings.cache_clear()


class TestSourceCreationIsAdminOnly:
    def _count(self):
        with session_scope() as s:
            return s.scalar(select(func.count(Source.id)).where(Source.name == SOURCE["name"]))

    def test_regular_user_cannot_create_a_source(self):
        make_user("bob", role="user")
        client = TestClient(app)
        login(client, "bob")
        r = client.post("/sources", json=SOURCE)
        assert r.status_code == 403 and self._count() == 0

    def test_anonymous_cannot_when_users_exist(self):
        make_user("bob")
        assert TestClient(app).post("/sources", json=SOURCE).status_code == 401
        assert self._count() == 0

    def test_admin_can_create_a_source(self):
        make_user("root", role="admin")
        client = TestClient(app)
        login(client, "root")
        r = client.post("/sources", json=SOURCE)
        assert r.status_code == 200 and r.json()["name"] == SOURCE["name"]
        assert self._count() == 1

    def test_master_key_automation_still_works(self, monkeypatch):
        monkeypatch.setenv("CTI_API_KEY", "mk-test")
        get_settings.cache_clear()
        with TestClient(app) as client:
            r = client.post("/sources", json=SOURCE, headers={"X-API-Key": "mk-test"})
            assert r.status_code == 200
        get_settings.cache_clear()

    def test_zero_user_open_mode_unchanged(self):
        # conftest enables CTI_OPEN_ACCESS: the legacy open mode keeps working.
        assert TestClient(app).post("/sources", json=SOURCE).status_code == 200

    def test_existing_source_listing_still_open_to_regular_users(self):
        make_user("bob")
        client = TestClient(app)
        login(client, "bob")
        assert client.get("/sources").status_code == 200
