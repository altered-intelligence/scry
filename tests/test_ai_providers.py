"""Provider management tests — bring-your-own-model endpoints and resolution.

No real network calls: frontier connection checks run against a missing SDK
or fail fast; Ollama auto-detect is never exercised here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import scry.api.ai as ai_mod
from scry.ai.providers.base import ChatChunk
from scry.ai.registry import resolve_ai_provider
from scry.crypto import decrypt, encrypt
from scry.main import app
from scry.models import LLMSetting

MODEL_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"


class FakeFrontierProvider:
    """Stand-in for a configured frontier provider."""

    name = "openai"
    display_name = "OpenAI"
    default_model = "gpt-fake"

    def __init__(self, *a, **k):
        pass

    def list_models(self):
        return []

    async def chat_stream(self, messages, model="", system="", max_tokens=512):
        yield ChatChunk(text="frontier answer [1]", done=True)


@pytest.fixture
def fake_model_file(tmp_path: Path) -> Path:
    p = tmp_path / MODEL_NAME
    p.write_bytes(b"fake-gguf")
    return p


@pytest.fixture
def ai_enabled(monkeypatch, fake_model_file):
    monkeypatch.setenv("CTI_ENABLE_AI_SEARCH", "true")
    monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(fake_model_file))
    from scry import config as _config

    _config.get_settings.cache_clear()
    yield fake_model_file
    _config.get_settings.cache_clear()


class TestProviderList:
    def test_lists_all_providers(self, ai_enabled):
        with TestClient(app) as client:
            r = client.get("/api/ai/provider")
            assert r.status_code == 200
            body = r.json()
        ids = [p["id"] for p in body["providers"]]
        assert ids == ["local", "ollama", "openai", "anthropic", "google", "xai"]
        assert body["active"] == "local"  # bundled model file exists

    def test_local_entry_reflects_model_presence(self, ai_enabled):
        with TestClient(app) as client:
            body = client.get("/api/ai/provider").json()
        local = next(p for p in body["providers"] if p["id"] == "local")
        assert local["available"] is True
        assert local["models"][0]["id"] == MODEL_NAME
        assert local["needs_api_key"] is False


class TestProviderConfigure:
    def test_unknown_provider_404(self, ai_enabled):
        with TestClient(app) as client:
            r = client.put("/api/ai/provider", json={"provider": "bogus"})
            assert r.status_code == 404

    def test_configure_openai_persists_and_masks_key(self, ai_enabled, session):
        with TestClient(app) as client:
            r = client.put(
                "/api/ai/provider",
                json={
                    "provider": "openai",
                    "api_key": "sk-test-123456",
                    "default_model": "gpt-4o-mini",
                },
            )
            assert r.status_code == 200
            entry = r.json()
        assert entry["configured"] is True
        assert entry["enabled"] is True
        assert entry["default_model"] == "gpt-4o-mini"
        # key never returned in clear; row stores it encrypted
        assert "sk-test-123456" not in str(entry)
        row = session.query(LLMSetting).filter_by(provider="openai").one()
        assert decrypt(row.api_key_encrypted) == "sk-test-123456"

    def test_enabling_second_provider_disables_first(self, ai_enabled, session):
        with TestClient(app) as client:
            client.put("/api/ai/provider", json={"provider": "openai", "api_key": "sk-a"})
            client.put("/api/ai/provider", json={"provider": "anthropic", "api_key": "sk-b"})
        openai = session.query(LLMSetting).filter_by(provider="openai").one()
        anthropic = session.query(LLMSetting).filter_by(provider="anthropic").one()
        assert openai.enabled is False
        assert anthropic.enabled is True

    def test_clear_api_key(self, ai_enabled, session):
        with TestClient(app) as client:
            client.put("/api/ai/provider", json={"provider": "openai", "api_key": "sk-a"})
            client.put("/api/ai/provider", json={"provider": "openai", "clear_api_key": True})
        row = session.query(LLMSetting).filter_by(provider="openai").one()
        assert row.api_key_encrypted is None


class TestResolution:
    def test_db_row_wins_over_local_fallback(self, ai_enabled, session):
        session.add(
            LLMSetting(
                provider="anthropic",
                api_key_encrypted=encrypt("sk-ant"),
                default_model="claude-fake",
                enabled=True,
            )
        )
        session.commit()
        provider, provider_id = resolve_ai_provider(session)
        assert provider_id == "anthropic"
        assert provider.default_model == "claude-fake"

    def test_local_fallback_when_no_db_row(self, ai_enabled, session):
        provider, provider_id = resolve_ai_provider(session)
        assert provider_id == "local"
        assert provider is not None


class TestAskWithFrontierProvider:
    def test_ask_uses_configured_frontier_model(self, ai_enabled, monkeypatch, seed_article):
        monkeypatch.setattr(ai_mod, "_resolve_provider", lambda session: FakeFrontierProvider())
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "lockbit hospitals"})
            assert r.status_code == 200
            body = r.json()
        assert body["answer"] == "frontier answer [1]"
        assert body["model"] == "openai/gpt-fake"
        assert body["sources"][0]["link"].startswith("/ui/articles/")


@pytest.fixture
def seed_article(session):
    from datetime import UTC, datetime

    from scry.models import Article, Source

    src = Source(
        name="T",
        type="vendor_blog",
        url="https://example.com",
        enabled=True,
        collection_policy="safe_public_web",
    )
    session.add(src)
    session.flush()
    art = Article(
        source_id=src.id,
        title="LockBit ransomware hits hospitals",
        url="https://example.com/lockbit",
        summary="LockBit affiliates breached three US hospitals.",
        extracted_text="LockBit affiliates breached three US hospitals using phishing.",
        ingested_at=datetime.now(UTC),
    )
    session.add(art)
    session.commit()
    return art
