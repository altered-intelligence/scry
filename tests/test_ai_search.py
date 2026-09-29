"""AI Search endpoint tests — the local LLM provider is stubbed; no real model needed."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import scry.api.ai as ai_mod
from scry.ai.providers.base import ChatChunk
from scry.main import app

MODEL_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"


class FakeLocalProvider:
    """Stand-in for LocalLlamaProvider — no llama_cpp, no GGUF inference."""

    name = "local"

    def __init__(self, model_path: Path, available: bool = True, answer: str = "ok [1]"):
        self._path = model_path
        self._available = available
        self._answer = answer
        self.model_loaded = False
        self.last_messages: list[dict] | None = None
        self.last_system: str = ""

    @property
    def model_path(self) -> Path:
        return self._path

    def is_available(self) -> bool:
        return self._available

    async def chat_stream(self, messages, model="", system="", max_tokens=512):
        self.last_messages = messages
        self.last_system = system
        if isinstance(self._answer, Exception):
            yield ChatChunk(error=str(self._answer), done=True)
            return
        yield ChatChunk(text=self._answer, done=True, tokens_in=10, tokens_out=5)


@pytest.fixture
def fake_model_file(tmp_path: Path) -> Path:
    p = tmp_path / MODEL_NAME
    p.write_bytes(b"fake-gguf")
    return p


@pytest.fixture
def ai_enabled(monkeypatch, fake_model_file):
    """Enable the flag, point at the fake model file, fresh settings cache."""
    monkeypatch.setenv("CTI_ENABLE_AI_SEARCH", "true")
    monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(fake_model_file))
    from scry import config as _config

    _config.get_settings.cache_clear()
    yield fake_model_file
    _config.get_settings.cache_clear()


@pytest.fixture
def fake_provider(ai_enabled, monkeypatch):
    provider = FakeLocalProvider(ai_enabled)
    monkeypatch.setattr(ai_mod, "_provider", lambda: provider)
    return provider


@pytest.fixture
def seed_article(session):
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


class TestStatusEndpoint:
    def test_enabled_by_default(self, fake_model_file, monkeypatch):
        monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(fake_model_file))
        from scry import config as _config

        _config.get_settings.cache_clear()
        try:
            with TestClient(app) as client:
                body = client.get("/api/ai/status").json()
                assert body["enabled"] is True
                assert body["model_present"] is True  # file exists even when feature off
                assert body["model_loaded"] is False
        finally:
            _config.get_settings.cache_clear()

    def test_model_missing(self, ai_enabled, monkeypatch):
        missing = ai_enabled.parent / "nope.gguf"
        monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(missing))
        from scry import config as _config

        _config.get_settings.cache_clear()
        with TestClient(app) as client:
            body = client.get("/api/ai/status").json()
            assert body["enabled"] is True
            assert body["model_present"] is False
            assert body["model_size_mb"] is None

    def test_ready(self, ai_enabled):
        with TestClient(app) as client:
            body = client.get("/api/ai/status").json()
            assert body["enabled"] is True
            assert body["model_present"] is True
            assert body["model_loaded"] is False  # lazy — no inference on status
            assert body["model_size_mb"] == 0
            assert body["model_path"] == str(ai_enabled)


class TestAskEndpoint:
    def test_disabled_flag_gives_403(self, monkeypatch):
        monkeypatch.setenv("CTI_ENABLE_AI_SEARCH", "false")
        from scry import config as _config

        _config.get_settings.cache_clear()
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "anything"})
            assert r.status_code == 403
            assert "CTI_ENABLE_AI_SEARCH" in r.json()["detail"]

    def test_empty_question_gives_422(self, ai_enabled):
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": ""})
            assert r.status_code == 422

    def test_model_missing_gives_503_with_setup_hint(self, ai_enabled, monkeypatch):
        monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(ai_enabled.parent / "nope.gguf"))
        from scry import config as _config

        _config.get_settings.cache_clear()
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "what ransomware?"})
            assert r.status_code == 503
            assert "scry ai-setup" in r.json()["detail"]

    def test_happy_path(self, fake_provider, seed_article):
        fake_provider._answer = "LockBit hit three US hospitals [1]."
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "lockbit hospitals"})
            assert r.status_code == 200
            body = r.json()
            assert body["answer"] == "LockBit hit three US hospitals [1]."
            assert body["model"] == MODEL_NAME
            assert isinstance(body["elapsed_ms"], int)
            # the seeded article was retrieved as source [1] with a UI link
            assert body["sources"][0]["n"] == 1
            assert body["sources"][0]["type"] == "article"
            assert body["sources"][0]["link"] == f"/ui/articles/{seed_article.id}"

    def test_prompt_contains_sources_and_question(self, fake_provider, seed_article):
        """Grounding contract: system prompt + numbered sources + question reach the model."""
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "lockbit hospitals"})
            assert r.status_code == 200
        assert "not in the collected data" in fake_provider.last_system
        user_msg = fake_provider.last_messages[0]["content"]
        assert "[1] (article) LockBit ransomware hits hospitals" in user_msg
        assert "QUESTION: lockbit hospitals" in user_msg

    def test_provider_error_gives_502(self, fake_provider):
        fake_provider._answer = RuntimeError("boom")
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "anything"})
            assert r.status_code == 502
            assert "Local model error" in r.json()["detail"]


class TestKeywordRetrieval:
    def test_keywords_strip_stopwords(self):
        assert ai_mod._keywords("What CVEs are in the KEV catalog?") == ["cves", "kev", "catalog"]

    def test_collect_sources_ranks_multi_keyword_hits_first(self, session, seed_article):
        sources = ai_mod._collect_sources(session, "lockbit hospitals phishing", limit=8)
        assert sources
        assert sources[0]["title"] == "LockBit ransomware hits hospitals"

    def test_collect_sources_empty_for_stopword_only_question(self, session):
        assert ai_mod._collect_sources(session, "what is the", limit=8) == []
