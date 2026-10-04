"""Tests for optional API-token auth on the REST routers (v0.4.0 step 1).

The dependency reads settings lazily per request, and conftest clears the
``get_settings`` lru_cache for every test, so setting ``CTI_API_KEY`` via
``monkeypatch.setenv`` (plus one explicit cache clear) is enough to switch
auth on/off within a test.
"""

import pytest
from fastapi.testclient import TestClient

from scry.config import get_settings
from scry.main import app

KEY = "test-key"


@pytest.fixture
def api_key(monkeypatch):
    """Configure a static API key and refresh the cached settings."""
    monkeypatch.setenv("CTI_API_KEY", KEY)
    get_settings.cache_clear()
    return KEY


def test_no_key_configured_endpoints_still_open():
    """Default (empty CTI_API_KEY): everything works without headers."""
    with TestClient(app) as client:
        assert client.get("/articles").status_code == 200
        assert client.get("/stats").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/api/ai/status").status_code == 200


def test_key_configured_missing_header_returns_401(api_key):
    with TestClient(app) as client:
        r = client.get("/articles")
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == "Bearer"


def test_key_configured_wrong_key_returns_401(api_key):
    with TestClient(app) as client:
        assert client.get("/articles", headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/articles", headers={"Authorization": "Bearer wrong"}).status_code == 401
        # Non-bearer schemes are not accepted.
        assert client.get("/articles", headers={"Authorization": f"Basic {KEY}"}).status_code == 401


def test_key_accepted_via_x_api_key_header(api_key):
    with TestClient(app) as client:
        r = client.get("/articles", headers={"X-API-Key": api_key})
        assert r.status_code == 200
        assert r.json() == []


def test_key_accepted_via_bearer_header(api_key):
    with TestClient(app) as client:
        r = client.get("/articles", headers={"Authorization": f"Bearer {api_key}"})
        assert r.status_code == 200
        assert r.json() == []


def test_health_stays_open_with_key(api_key):
    """Monitoring probe must stay reachable without a key."""
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


def test_ai_status_stays_open_but_provider_list_requires_the_key(api_key):
    """Status is a harmless probe; the provider list exposes base URLs, masked
    keys, and connection errors, so it needs the key (or a session)."""
    with TestClient(app) as client:
        assert client.get("/api/ai/status").status_code == 200
        assert client.get("/api/ai/provider").status_code == 401
        assert client.get("/api/ai/provider", headers={"X-API-Key": api_key}).status_code == 200


def test_ui_routes_not_authenticated(api_key):
    """HTML UI routes live outside the API routers and never require the key."""
    with TestClient(app) as client:
        assert client.get("/ui/search").status_code == 200
