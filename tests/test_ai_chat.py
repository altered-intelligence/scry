"""AI Search conversation memory tests — ChatSession/ChatMessage wiring.

Follows the test_ai_search.py stub-provider pattern: the local LLM provider
is replaced with a fake so no real model is needed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import scry.api.ai as ai_mod
from scry.ai.providers.base import ChatChunk
from scry.main import app
from scry.models import ChatMessage, ChatSession

MODEL_NAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"


class FakeLocalProvider:
    """Stand-in for LocalLlamaProvider — records the messages it receives."""

    name = "local"

    def __init__(self, model_path: Path, available: bool = True, answer: str = "ok [1]"):
        self._path = model_path
        self._available = available
        self._answer = answer
        self.model_loaded = False
        self.calls: list[list[dict]] = []
        self.last_system: str = ""

    @property
    def model_path(self) -> Path:
        return self._path

    def is_available(self) -> bool:
        return self._available

    async def chat_stream(self, messages, model="", system="", max_tokens=512):
        self.calls.append(messages)
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
    monkeypatch.setenv("CTI_ENABLE_AI_SEARCH", "true")
    monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(fake_model_file))
    from scry import config as _config

    _config.get_settings.cache_clear()
    yield fake_model_file
    _config.get_settings.cache_clear()


@pytest.fixture
def fake_provider(ai_enabled, monkeypatch):
    provider = FakeLocalProvider(ai_enabled)
    monkeypatch.setattr(ai_mod, "_resolve_provider", lambda session: provider)
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


@pytest.fixture
def chat_session(session):
    s = ChatSession(title="New conversation")
    session.add(s)
    session.commit()
    return s


def _messages_of(session, session_id) -> list[ChatMessage]:
    return (
        session.query(ChatMessage)
        .filter_by(session_id=session_id)
        .order_by(ChatMessage.id)
        .all()
    )


class TestAskWithSession:
    def test_persists_exchange_and_returns_session_id(
        self, fake_provider, seed_article, chat_session, session
    ):
        fake_provider._answer = "LockBit hit three US hospitals [1]."
        with TestClient(app) as client:
            r = client.post(
                "/api/ai/ask",
                json={"question": "which ransomware hit hospitals?", "session_id": chat_session.id},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["answer"] == "LockBit hit three US hospitals [1]."
        assert body["session_id"] == chat_session.id

        msgs = _messages_of(session, chat_session.id)
        assert [m.role for m in msgs] == ["user", "assistant"]
        assert msgs[0].content == "which ransomware hit hospitals?"
        assert msgs[1].content == body["answer"]
        assert msgs[1].model_provider == "local"
        assert msgs[1].model_id == MODEL_NAME
        assert msgs[1].sources == body["sources"]
        assert msgs[1].duration_ms == body["elapsed_ms"]
        session.expire_all()
        assert session.get(ChatSession, chat_session.id).message_count == 2

    def test_title_auto_set_from_first_question(self, fake_provider, chat_session, session):
        with TestClient(app) as client:
            r = client.post(
                "/api/ai/ask",
                json={"question": "what do we know about LockBit activity?", "session_id": chat_session.id},
            )
        assert r.status_code == 200
        session.expire_all()
        assert session.get(ChatSession, chat_session.id).title == "what do we know about LockBit activity?"

    def test_renamed_title_not_overwritten(self, fake_provider, chat_session, session):
        chat_session.title = "My threat hunt"
        session.commit()
        with TestClient(app) as client:
            r = client.post(
                "/api/ai/ask", json={"question": "anything else?", "session_id": chat_session.id}
            )
        assert r.status_code == 200
        session.expire_all()
        assert session.get(ChatSession, chat_session.id).title == "My threat hunt"

    def test_followup_sends_prior_turns_to_model(
        self, fake_provider, seed_article, chat_session, session
    ):
        with TestClient(app) as client:
            r1 = client.post(
                "/api/ai/ask",
                json={"question": "which ransomware hit hospitals?", "session_id": chat_session.id},
            )
            assert r1.status_code == 200
            fake_provider._answer = "It also hit a clinic [1]."
            r2 = client.post(
                "/api/ai/ask",
                json={"question": "did it hit anything else?", "session_id": chat_session.id},
            )
            assert r2.status_code == 200

        # Second call: history (user+assistant of turn 1) precedes the new
        # user prompt; first call was a bare single user message.
        assert len(fake_provider.calls) == 2
        followup = fake_provider.calls[1]
        assert len(followup) == 3
        assert followup[0] == {"role": "user", "content": "which ransomware hit hospitals?"}
        assert followup[1] == {"role": "assistant", "content": "ok [1]"}
        assert followup[2]["role"] == "user"
        assert "did it hit anything else?" in followup[2]["content"]
        # The system prompt notes the continuing conversation.
        assert "conversation so far" in fake_provider.last_system

    def test_history_caps_at_eight_turns(self, fake_provider, chat_session, session):
        for i in range(10):
            session.add(
                ChatMessage(session_id=chat_session.id, role="user", content=f"q{i}")
            )
            session.add(
                ChatMessage(session_id=chat_session.id, role="assistant", content=f"a{i}")
            )
        chat_session.message_count = 20
        chat_session.title = "long thread"
        session.commit()

        with TestClient(app) as client:
            r = client.post(
                "/api/ai/ask",
                json={"question": "latest?", "session_id": chat_session.id},
            )
        assert r.status_code == 200
        msgs = fake_provider.calls[0]
        # 8 history turns (16 messages) + the new user prompt = 17.
        assert len(msgs) == 17
        assert msgs[0]["content"] == "q2"  # oldest included turn
        assert "QUESTION: latest?" in msgs[-1]["content"]

    def test_unknown_session_gives_404(self, fake_provider):
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "hi", "session_id": 9999})
        assert r.status_code == 404

    def test_archived_session_gives_409(self, fake_provider, chat_session, session):
        chat_session.archived = True
        session.commit()
        with TestClient(app) as client:
            r = client.post(
                "/api/ai/ask", json={"question": "hi", "session_id": chat_session.id}
            )
        assert r.status_code == 409

    def test_provider_error_nothing_persisted(self, fake_provider, chat_session, session):
        fake_provider._answer = RuntimeError("boom")
        with TestClient(app) as client:
            r = client.post(
                "/api/ai/ask", json={"question": "hi", "session_id": chat_session.id}
            )
        assert r.status_code == 502
        assert _messages_of(session, chat_session.id) == []


class TestSessionlessAsk:
    def test_response_shape_unchanged_and_no_session_created(
        self, fake_provider, seed_article, session
    ):
        fake_provider._answer = "LockBit hit three US hospitals [1]."
        with TestClient(app) as client:
            r = client.post("/api/ai/ask", json={"question": "lockbit hospitals"})
        assert r.status_code == 200
        body = r.json()
        # Keys the Dashboard Ask widget consumes — nothing removed/renamed.
        for key in ("answer", "sources", "model", "elapsed_ms"):
            assert key in body
        assert body["sources"][0]["link"] == f"/ui/articles/{seed_article.id}"
        assert "session_id" not in body
        assert session.query(ChatSession).count() == 0
        assert session.query(ChatMessage).count() == 0


class TestSessionEndpoints:
    def test_list_sorted_by_updated_desc_and_hides_archived(
        self, fake_provider, chat_session, session
    ):
        from datetime import timedelta

        other = ChatSession(title="older")
        session.add(other)
        archived = ChatSession(title="gone", archived=True)
        session.add(archived)
        session.flush()
        # Deterministic ordering: "older" was last touched longest ago.
        chat_session.updated_at = datetime.now(UTC) - timedelta(hours=2)
        other.updated_at = datetime.now(UTC) - timedelta(hours=1)
        session.commit()

        with TestClient(app) as client:
            r = client.get("/api/ai/sessions")
        assert r.status_code == 200
        ids = [s["id"] for s in r.json()["sessions"]]
        assert chat_session.id in ids
        assert other.id in ids
        assert archived.id not in ids
        # updated desc → the never-touched "older" row was committed last.
        assert ids[0] == other.id
        entry = r.json()["sessions"][0]
        assert set(entry) == {"id", "title", "message_count", "updated_at", "archived"}

        with TestClient(app) as client:
            r2 = client.get("/api/ai/sessions", params={"include_archived": "true"})
        assert archived.id in [s["id"] for s in r2.json()["sessions"]]

    def test_rename(self, chat_session):
        with TestClient(app) as client:
            r = client.post(
                "/api/ai/sessions", json={"id": chat_session.id, "title": "Ransomware follow-ups"}
            )
        assert r.status_code == 200
        assert r.json()["title"] == "Ransomware follow-ups"

    def test_rename_unknown_gives_404(self):
        with TestClient(app) as client:
            r = client.post("/api/ai/sessions", json={"id": 4242, "title": "nope"})
        assert r.status_code == 404

    def test_delete_cascades_messages(self, fake_provider, chat_session, session):
        with TestClient(app) as client:
            client.post(
                "/api/ai/ask", json={"question": "hi", "session_id": chat_session.id}
            )
        assert session.query(ChatMessage).count() == 2

        with TestClient(app) as client:
            r = client.delete(f"/api/ai/sessions/{chat_session.id}")
        assert r.status_code == 200
        assert r.json() == {"deleted": chat_session.id}
        session.expunge(chat_session)  # row was deleted in the endpoint's session
        assert session.get(ChatSession, chat_session.id) is None
        assert session.query(ChatMessage).count() == 0

    def test_delete_unknown_gives_404(self):
        with TestClient(app) as client:
            r = client.delete("/api/ai/sessions/4242")
        assert r.status_code == 404

    def test_detail_returns_messages(self, fake_provider, chat_session, session):
        with TestClient(app) as client:
            client.post(
                "/api/ai/ask",
                json={"question": "which ransomware?", "session_id": chat_session.id},
            )
            r = client.get(f"/api/ai/sessions/{chat_session.id}")
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == chat_session.id
        assert body["title"] == "which ransomware?"
        assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
        assistant = body["messages"][1]
        assert set(assistant) == {
            "id",
            "role",
            "content",
            "sources",
            "model_provider",
            "model_id",
            "duration_ms",
            "error",
            "created_at",
        }
        assert assistant["model_provider"] == "local"
        assert assistant["model_id"] == MODEL_NAME

    def test_detail_unknown_gives_404(self):
        with TestClient(app) as client:
            r = client.get("/api/ai/sessions/4242")
        assert r.status_code == 404
