from fastapi.testclient import TestClient

from scry.config import get_settings
from scry.main import app


def test_missing_installation_token_rejected(monkeypatch):
    monkeypatch.setenv("CTI_SETUP_TOKEN", "")
    get_settings.cache_clear()
    with TestClient(app) as client:
        assert client.post("/setup", data={"username": "attacker"}).status_code == 403


def test_wrong_installation_token_rejected(monkeypatch):
    monkeypatch.setenv("CTI_SETUP_TOKEN", "a" * 32)
    get_settings.cache_clear()
    with TestClient(app) as client:
        assert (
            client.post("/setup", headers={"X-Setup-Token": "wrong"}).status_code == 403
        )
