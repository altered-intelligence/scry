"""Report brief tests — the LLM provider layer is stubbed; no real model needed."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import scry.reporting.brief as brief_mod
from scry.ai.errors import AskError
from scry.ai.providers.base import ChatChunk
from scry.main import app

MODEL_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"


class FakeProvider:
    """Stand-in for a real LLM provider — records prompts, streams a canned answer."""

    name = "local"

    def __init__(self, answer: str = "Executive briefing.", model_path: Path | None = None):
        self._answer = answer
        self._path = model_path or Path("/models") / MODEL_NAME
        self.calls = 0
        self.last_messages: list[dict] | None = None
        self.last_system: str = ""

    @property
    def model_path(self) -> Path:
        return self._path

    async def chat_stream(self, messages, model="", system="", max_tokens=512):
        self.calls += 1
        self.last_messages = messages
        self.last_system = system
        if isinstance(self._answer, Exception):
            yield ChatChunk(error=str(self._answer), done=True)
            return
        yield ChatChunk(text=self._answer, done=True, tokens_in=10, tokens_out=5)


@pytest.fixture(autouse=True)
def _fresh_cache():
    brief_mod.clear_brief_cache()
    yield
    brief_mod.clear_brief_cache()


@pytest.fixture
def fake_provider(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(brief_mod, "resolve_ai_provider", lambda session: (provider, "stub"))
    return provider


class TestGenerateBrief:
    async def test_happy_path(self, session, fake_provider):
        fake_provider._answer = "## Top developments\n- Nothing new."
        result = await brief_mod.generate_brief(session, "daily")
        assert result["brief"] == "## Top developments\n- Nothing new."
        assert result["model"] == f"local/{MODEL_NAME}"
        assert result["scope"] == "daily"
        assert result["cached"] is False
        assert isinstance(result["elapsed_ms"], int)
        assert result["generated_at"]

    async def test_weekly_scope_uses_weekly_report(self, session, fake_provider):
        await brief_mod.generate_brief(session, "weekly")
        user_msg = fake_provider.last_messages[0]["content"]
        assert "Weekly report to synthesize:" in user_msg
        assert "# CTI Weekly Report" in user_msg

    async def test_empty_report_prompt_says_so(self, session, fake_provider):
        """Empty DB → report has zero activity; prompt must instruct the model to say so."""
        await brief_mod.generate_brief(session, "daily")
        assert "nothing notable" in fake_provider.last_system
        user_msg = fake_provider.last_messages[0]["content"]
        assert "# CTI Daily Report" in user_msg  # the plain-text report was piped through

    async def test_cache_returns_cached_flag(self, session, fake_provider):
        first = await brief_mod.generate_brief(session, "daily")
        second = await brief_mod.generate_brief(session, "daily")
        assert first["cached"] is False
        assert second["cached"] is True
        assert second["brief"] == first["brief"]
        assert fake_provider.calls == 1  # model ran once

    async def test_cache_keyed_by_scope(self, session, fake_provider):
        await brief_mod.generate_brief(session, "daily")
        weekly = await brief_mod.generate_brief(session, "weekly")
        assert weekly["cached"] is False
        assert fake_provider.calls == 2

    async def test_bogus_scope_rejected(self, session, fake_provider):
        with pytest.raises(AskError) as exc_info:
            await brief_mod.generate_brief(session, "hourly")
        assert exc_info.value.status_code == 422
        assert fake_provider.calls == 0

    async def test_no_provider_gives_503(self, session, monkeypatch):
        monkeypatch.setattr(brief_mod, "resolve_ai_provider", lambda session: (None, ""))
        with pytest.raises(AskError) as exc_info:
            await brief_mod.generate_brief(session, "daily")
        assert exc_info.value.status_code == 503
        assert "No LLM provider available" in exc_info.value.detail

    async def test_provider_error_gives_502(self, session, fake_provider):
        fake_provider._answer = RuntimeError("boom")
        with pytest.raises(AskError) as exc_info:
            await brief_mod.generate_brief(session, "daily")
        assert exc_info.value.status_code == 502
        assert "Model error" in exc_info.value.detail


class TestBriefEndpoint:
    def test_happy_path(self, fake_provider):
        fake_provider._answer = "## Top developments\n- CVE-2024-0001 exploited."
        with TestClient(app) as client:
            r = client.post("/api/reports/brief", params={"scope": "daily"})
            assert r.status_code == 200
            body = r.json()
            assert body["brief"] == "## Top developments\n- CVE-2024-0001 exploited."
            assert body["scope"] == "daily"
            assert body["cached"] is False

    def test_default_scope_is_daily(self, fake_provider):
        with TestClient(app) as client:
            r = client.post("/api/reports/brief")
            assert r.status_code == 200
            assert r.json()["scope"] == "daily"

    def test_second_call_is_cached(self, fake_provider):
        with TestClient(app) as client:
            assert client.post("/api/reports/brief").json()["cached"] is False
            assert client.post("/api/reports/brief").json()["cached"] is True
            assert fake_provider.calls == 1

    def test_bogus_scope_gives_422(self, fake_provider):
        with TestClient(app) as client:
            r = client.post("/api/reports/brief", params={"scope": "hourly"})
            assert r.status_code == 422

    def test_sibling_path_alias(self, fake_provider):
        """Registered under both /reports/brief (sibling of /reports/daily) and /api/reports/brief."""
        with TestClient(app) as client:
            assert client.post("/reports/brief").status_code == 200
            assert client.post("/api/reports/brief").status_code == 200

    def test_no_provider_gives_503(self, monkeypatch):
        monkeypatch.setattr(brief_mod, "resolve_ai_provider", lambda session: (None, ""))
        with TestClient(app) as client:
            r = client.post("/api/reports/brief", params={"scope": "weekly"})
            assert r.status_code == 503
            assert "No LLM provider available" in r.json()["detail"]
