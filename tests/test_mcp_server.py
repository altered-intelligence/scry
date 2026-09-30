"""MCP server tests — tool bodies are exercised directly with a test session.

The FastMCP wrappers only add session management, so testing the plain
`tool_scry_*` functions against the conftest fixtures covers the logic; a
light check asserts all six tools are registered on the built server.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import scry.api.ai as ai_mod
import scry.mcp_server as mcp_mod

TOOL_NAMES = {
    "scry_health",
    "scry_stats",
    "scry_search",
    "scry_observables",
    "scry_alerts",
    "scry_ask",
}


@pytest.fixture
def seed_intel(session):
    """A source + article + observable + one alert of each delivery state."""
    from scry.models import Alert, Article, Observable, Source

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
    ob = Observable(
        type="domain",
        value="evil-lockbit.example",
        normalized_value="evil-lockbit.example",
        risk_score=88.0,
        status="active",
        tags=["ransomware"],
    )
    alert_open = Alert(
        trigger="kev_cve", title="New KEV CVE", severity="high", confidence=80, delivered=False
    )
    alert_done = Alert(
        trigger="kev_cve", title="Old KEV CVE", severity="low", confidence=70, delivered=True
    )
    session.add_all([art, ob, alert_open, alert_done])
    session.commit()
    return {"article": art, "observable": ob, "alerts": [alert_open, alert_done]}


class TestServerBuild:
    def test_all_six_tools_registered(self):
        server = mcp_mod.build_server()
        assert set(server._tool_manager._tools) == TOOL_NAMES


class TestHealth:
    def test_health_ok(self, session):
        body = mcp_mod.tool_scry_health(session)
        assert body["status"] == "ok"
        assert body["db_ok"] is True
        assert isinstance(body["version"], str) and body["version"]
        assert isinstance(body["uptime_seconds"], int)


class TestStats:
    def test_counts_match_seeded_rows(self, session, seed_intel):
        stats = mcp_mod.tool_scry_stats(session)
        assert stats["articles"] == 1
        assert stats["observables"] == 1
        assert stats["alerts"] == 2
        assert stats["sources"] == 1
        # same shape as the /stats endpoint
        for key in ("entities", "claims", "cves", "open_reviews"):
            assert key in stats


class TestSearch:
    def test_search_hit_shape_and_link(self, session, seed_intel):
        hits = mcp_mod.tool_scry_search(session, "lockbit", limit=10)
        assert isinstance(hits, list) and hits
        hit = hits[0]
        assert hit["object_type"] == "article"
        assert hit["object_id"] == seed_intel["article"].id
        assert hit["title"] == "LockBit ransomware hits hospitals"
        assert "LockBit" in hit["snippet"]
        assert hit["link"] == f"/ui/articles/{seed_intel['article'].id}"
        assert isinstance(hit["score"], float)

    def test_search_no_match(self, session, seed_intel):
        assert mcp_mod.tool_scry_search(session, "zzzz-nothing-matches") == []


class TestObservables:
    def test_unfiltered_listing(self, session, seed_intel):
        rows = mcp_mod.tool_scry_observables(session)
        assert len(rows) == 1
        row = rows[0]
        assert row["type"] == "domain"
        assert row["normalized_value"] == "evil-lockbit.example"
        assert row["risk_score"] == 88.0
        assert row["tags"] == ["ransomware"]

    def test_filter_by_query_and_type(self, session, seed_intel):
        assert len(mcp_mod.tool_scry_observables(session, query="lockbit")) == 1
        assert mcp_mod.tool_scry_observables(session, query="nope") == []
        assert len(mcp_mod.tool_scry_observables(session, type="domain")) == 1
        assert mcp_mod.tool_scry_observables(session, type="ip") == []


class TestAlerts:
    def test_acknowledged_excluded_by_default(self, session, seed_intel):
        rows = mcp_mod.tool_scry_alerts(session)
        assert len(rows) == 1
        assert rows[0]["title"] == "New KEV CVE"
        assert rows[0]["delivered"] is False
        assert rows[0]["severity"] == "high"
        assert rows[0]["created_at"]  # iso timestamp present

    def test_include_acknowledged(self, session, seed_intel):
        rows = mcp_mod.tool_scry_alerts(session, include_acknowledged=True)
        assert len(rows) == 2
        assert rows[0]["id"] > rows[1]["id"]  # newest first


class TestAsk:
    async def test_no_provider_returns_error_dict(self, session, seed_intel, monkeypatch):
        monkeypatch.setattr(ai_mod, "_resolve_provider", lambda s: None)
        result = await mcp_mod.tool_scry_ask(session, "what ransomware?")
        assert "error" in result
        assert result["error_status"] == 503
        assert result["sources"] == []

    async def test_ask_happy_path_with_stub_provider(self, session, seed_intel, monkeypatch):
        from scry.ai.providers.base import ChatChunk

        class FakeProvider:
            name = "stub"

            async def chat_stream(self, messages, model="", system="", max_tokens=512):
                yield ChatChunk(text="LockBit hit hospitals [1].", done=True)

            def list_models(self):
                return []

        provider = FakeProvider()
        monkeypatch.setattr(ai_mod, "_resolve_provider", lambda s: provider)
        monkeypatch.setattr(ai_mod, "_provider_model", lambda p: "stub-model")
        result = await mcp_mod.tool_scry_ask(session, "lockbit hospitals")
        assert result["answer"] == "LockBit hit hospitals [1]."
        assert result["model"] == "stub/stub-model"
        assert isinstance(result["elapsed_ms"], int)
        assert result["sources"][0]["link"] == f"/ui/articles/{seed_intel['article'].id}"
