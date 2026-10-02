"""Tests for the setup-required default (CTI_OPEN_ACCESS escape hatch).

With zero users, no master key, and the escape hatch off, the app must not
serve anything: UI routes redirect to /setup, API routes 403. Setting
CTI_OPEN_ACCESS=true restores the legacy zero-user open mode (covered here
explicitly even though conftest enables it for the rest of the suite). A
master key with zero users keeps the previous behavior (API key-required,
UI open).
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from scry.config import get_settings
from scry.main import app


@pytest.fixture
def setup_mode(monkeypatch):
    """Zero users (per-test DB), no master key, escape hatch OFF."""
    monkeypatch.setenv("CTI_OPEN_ACCESS", "false")
    monkeypatch.setenv("CTI_API_KEY", "")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _setup_csrf(client: TestClient) -> str:
    r = client.get("/setup")
    assert r.status_code == 200
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    assert m, "setup page must carry a CSRF token"
    return m.group(1)


class TestSetupRequiredMode:
    def test_dashboard_redirects_to_setup(self, setup_mode):
        with TestClient(app) as client:
            r = client.get("/", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/setup"

    def test_ui_routes_redirect_to_setup(self, setup_mode):
        with TestClient(app) as client:
            for path in ("/ui/search", "/ui/articles", "/ui/reviews", "/profile", "/admin"):
                r = client.get(path, follow_redirects=False)
                assert r.status_code == 303, path
                assert r.headers["location"] == "/setup", path

    def test_api_routes_403_with_setup_hint(self, setup_mode):
        with TestClient(app) as client:
            r = client.get("/sources")
            assert r.status_code == 403
            assert "/setup" in r.json()["detail"]
            assert client.get("/articles").status_code == 403
            assert client.get("/stats").status_code == 403

    def test_exempt_routes_stay_reachable(self, setup_mode):
        with TestClient(app) as client:
            assert client.get("/setup").status_code == 200
            assert client.get("/login").status_code == 200
            assert client.get("/health").status_code == 200
            assert client.get("/api/ai/status").status_code == 200
            # Static mount is not gated — a missing file 404s instead of
            # redirecting to /setup.
            assert client.get("/static/definitely-missing.css").status_code == 404

    def test_setup_completion_unlocks_normal_auth(self, setup_mode):
        with TestClient(app) as client:
            csrf = _setup_csrf(client)
            r = client.post(
                "/setup",
                data={
                    "csrf": csrf,
                    "username": "root",
                    "password": "Sup3r!pass",
                    "confirm_password": "Sup3r!pass",
                },
                follow_redirects=False,
            )
            assert r.status_code == 303
            # The installer is signed in: UI + API work with the session.
            assert client.get("/").status_code == 200
            assert client.get("/sources").status_code == 200
            # Normal auth now applies to everyone else (mode never returns).
            anon = TestClient(app)
            assert anon.get("/sources").status_code == 401
            r = anon.get("/", follow_redirects=False)
            assert r.headers["location"] == "/login"
            assert anon.get("/setup").status_code == 404


class TestOpenAccessEscapeHatch:
    def test_zero_user_open_mode_preserved(self, monkeypatch):
        monkeypatch.setenv("CTI_OPEN_ACCESS", "true")
        monkeypatch.setenv("CTI_API_KEY", "")
        get_settings.cache_clear()
        try:
            with TestClient(app) as client:
                assert client.get("/").status_code == 200
                assert client.get("/ui/search").status_code == 200
                assert client.get("/sources").status_code == 200
        finally:
            get_settings.cache_clear()


class TestMasterKeyWithZeroUsers:
    def test_key_required_on_api_ui_stays_open(self, monkeypatch):
        monkeypatch.setenv("CTI_OPEN_ACCESS", "false")
        monkeypatch.setenv("CTI_API_KEY", "mk-test")
        get_settings.cache_clear()
        try:
            with TestClient(app) as client:
                assert client.get("/sources").status_code == 401
                assert client.get("/sources", headers={"X-API-Key": "mk-test"}).status_code == 200
                # Current zero-user UI behavior is preserved (unchanged).
                assert client.get("/").status_code == 200
        finally:
            get_settings.cache_clear()
