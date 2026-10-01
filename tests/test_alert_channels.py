"""Tests for alert notification channels, the /alerts/test endpoint,
and auto-evaluation after ingest.

HTTP posts (Slack/Teams/generic webhook) are mocked with respx; smtplib and
subprocess are monkeypatched; settings are switched via env vars plus an
explicit get_settings cache clear (same pattern as tests/test_api_auth.py).
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

import scry.alerting.channels as channels_mod
from scry.config import get_settings
from scry.models import Alert


def _alert() -> Alert:
    return Alert(
        trigger="test",
        title="Test alert",
        summary="summary",
        severity="high",
        why_it_matters="because",
        recommended_action="do something",
        related={"cve_id": "CVE-2024-0001"},
        dedup_key="test:1",
    )


@pytest.fixture
def outbound_on(monkeypatch):
    monkeypatch.setenv("CTI_ENABLE_OUTBOUND_ALERTS", "true")
    get_settings.cache_clear()
    return True


@pytest.fixture
def fake_smtp(monkeypatch):
    """Record smtplib usage instead of sending mail."""
    calls: dict[str, list] = {"SMTP_SSL": [], "SMTP": [], "login": [], "send_message": []}

    class _FakeSmtp:
        def __init__(self, *args, **kwargs):
            calls["SMTP_SSL" if args and args[1] == 465 else "SMTP"].append((args, kwargs))

        def starttls(self):
            calls["starttls"] = True

        def login(self, user, password):
            calls["login"].append((user, password))

        def send_message(self, msg):
            calls["send_message"].append(msg)

        def quit(self):
            pass

    monkeypatch.setattr(channels_mod.smtplib, "SMTP_SSL", _FakeSmtp)
    monkeypatch.setattr(channels_mod.smtplib, "SMTP", _FakeSmtp)
    return calls


@pytest.fixture
def fake_desktop(monkeypatch):
    runs: list[list[str]] = []

    class _Result:
        returncode = 0

    def _run(cmd, **kwargs):
        runs.append(cmd)
        return _Result()

    monkeypatch.setattr(channels_mod.subprocess, "run", _run)
    monkeypatch.setattr(channels_mod.sys, "platform", "darwin")
    return runs


SLACK = "https://hooks.slack.test/services/XXX"
TEAMS = "https://teams.test/webhook"
HOOK = "https://generic.test/hook"


class TestDeliver:
    @respx.mock
    def test_routes_to_configured_channels_only(self, outbound_on, monkeypatch):
        monkeypatch.setenv("CTI_SLACK_WEBHOOK_URL", SLACK)
        monkeypatch.setenv("CTI_WEBHOOK_URL", HOOK)
        get_settings.cache_clear()
        slack_route = respx.post(SLACK).mock(return_value=httpx.Response(200))
        hook_route = respx.post(HOOK).mock(return_value=httpx.Response(200))
        respx.post(TEAMS).mock(return_value=httpx.Response(200))

        assert channels_mod.deliver(_alert()) is True
        assert slack_route.called
        assert hook_route.called
        # Teams not configured → no request even though a route exists.
        requested_urls = [str(c.request.url) for c in respx.calls]
        assert TEAMS not in requested_urls
        # Generic webhook payload carries the structured alert.
        import json

        body = json.loads(hook_route.calls.last.request.content)
        assert body["alert"]["title"] == "Test alert"
        assert body["alert"]["severity"] == "high"
        assert body["alert"]["related"] == {"cve_id": "CVE-2024-0001"}
        assert "text" in body

    @respx.mock
    def test_outbound_disabled_sends_nothing(self, monkeypatch):
        monkeypatch.setenv("CTI_ENABLE_OUTBOUND_ALERTS", "false")
        monkeypatch.setenv("CTI_SLACK_WEBHOOK_URL", SLACK)
        get_settings.cache_clear()
        respx.post(SLACK).mock(return_value=httpx.Response(200))

        assert channels_mod.deliver(_alert()) is False
        assert len(respx.calls) == 0

    @respx.mock
    def test_channel_failure_isolated(self, outbound_on, monkeypatch):
        """A failing webhook must not stop the other channels."""
        monkeypatch.setenv("CTI_SLACK_WEBHOOK_URL", SLACK)
        monkeypatch.setenv("CTI_WEBHOOK_URL", HOOK)
        get_settings.cache_clear()
        respx.post(SLACK).mock(return_value=httpx.Response(200))
        respx.post(HOOK).mock(return_value=httpx.Response(500))

        assert channels_mod.deliver(_alert()) is True
        assert len(respx.calls) == 2

    @respx.mock
    def test_email_channel(self, outbound_on, monkeypatch, fake_smtp):
        monkeypatch.setenv("CTI_ALERT_EMAIL_FROM", "scry@example.com")
        monkeypatch.setenv("CTI_ALERT_EMAIL_TO", "soc@example.com")
        monkeypatch.setenv("CTI_SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("CTI_SMTP_PORT", "465")
        get_settings.cache_clear()

        assert channels_mod.deliver(_alert()) is True
        assert len(fake_smtp["SMTP_SSL"]) == 1
        msg = fake_smtp["send_message"][0]
        assert msg["Subject"] == "[scry] high: Test alert"
        assert msg["To"] == "soc@example.com"
        assert "do something" in msg.get_content()

    @respx.mock
    def test_email_requires_smtp_host(self, outbound_on, monkeypatch, fake_smtp):
        monkeypatch.setenv("CTI_ALERT_EMAIL_FROM", "scry@example.com")
        monkeypatch.setenv("CTI_ALERT_EMAIL_TO", "soc@example.com")
        get_settings.cache_clear()

        assert channels_mod.deliver(_alert()) is False
        assert fake_smtp["send_message"] == []

    def test_desktop_channel(self, outbound_on, monkeypatch, fake_desktop):
        monkeypatch.setenv("CTI_NOTIFY_DESKTOP", "true")
        get_settings.cache_clear()

        assert channels_mod.deliver(_alert()) is True
        assert len(fake_desktop) == 1
        assert fake_desktop[0][0] == "osascript"
        assert "Test alert" in fake_desktop[0][2]

    def test_desktop_skipped_off_flag(self, outbound_on, monkeypatch, fake_desktop):
        monkeypatch.setenv("CTI_NOTIFY_DESKTOP", "false")
        get_settings.cache_clear()

        assert channels_mod.deliver(_alert()) is False
        assert fake_desktop == []


class TestDeliverTest:
    @respx.mock
    def test_returns_only_configured_channels(self, outbound_on, monkeypatch):
        monkeypatch.setenv("CTI_SLACK_WEBHOOK_URL", SLACK)
        monkeypatch.setenv("CTI_WEBHOOK_URL", HOOK)
        get_settings.cache_clear()
        respx.post(SLACK).mock(return_value=httpx.Response(200))
        respx.post(HOOK).mock(return_value=httpx.Response(200))

        result = channels_mod.deliver_test()
        assert result == {"slack": True, "webhook": True}

    @respx.mock
    def test_failure_reported_false(self, outbound_on, monkeypatch):
        monkeypatch.setenv("CTI_TEAMS_WEBHOOK_URL", TEAMS)
        get_settings.cache_clear()
        respx.post(TEAMS).mock(return_value=httpx.Response(500))

        assert channels_mod.deliver_test() == {"teams": False}

    @respx.mock
    def test_disabled_returns_empty(self, monkeypatch):
        monkeypatch.setenv("CTI_ENABLE_OUTBOUND_ALERTS", "false")
        monkeypatch.setenv("CTI_SLACK_WEBHOOK_URL", SLACK)
        get_settings.cache_clear()
        respx.post(SLACK).mock(return_value=httpx.Response(200))

        assert channels_mod.deliver_test() == {}
        assert len(respx.calls) == 0


class TestAlertsTestEndpoint:
    def test_endpoint_returns_per_channel_dict(self, outbound_on, monkeypatch):
        monkeypatch.setattr("scry.api.router.deliver_test", lambda: {"slack": True, "webhook": False})
        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/alerts/test")
        assert r.status_code == 200
        assert r.json() == {"slack": True, "webhook": False}

    def test_endpoint_requires_auth_when_key_set(self, outbound_on, monkeypatch):
        monkeypatch.setenv("CTI_API_KEY", "k")
        get_settings.cache_clear()
        monkeypatch.setattr("scry.api.router.deliver_test", lambda: {})
        from scry.main import app

        with TestClient(app) as client:
            assert client.post("/alerts/test").status_code == 401
            assert client.post("/alerts/test", headers={"X-API-Key": "k"}).status_code == 200


class TestPostIngestEvaluate:
    def _patch_ingest(self, monkeypatch):
        class _FakeIngestion:
            def __init__(self, session):
                pass

            async def ingest_all(self):
                return {"articles": 2}

        class _FakePipeline:
            def __init__(self, session):
                pass

            def process_article(self, art):
                pass

        monkeypatch.setattr("scry.api.router.IngestionEngine", _FakeIngestion)
        monkeypatch.setattr("scry.api.router.CTIPipeline", _FakePipeline)

    def test_evaluate_invoked_after_ingest(self, monkeypatch):
        from scry.api import router as router_mod

        self._patch_ingest(monkeypatch)
        calls: list[bool] = []
        monkeypatch.setattr(router_mod.AlertEngine, "evaluate", lambda self: calls.append(True) or [])
        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/ingest/run")
        assert r.status_code == 200
        assert calls == [True]
        assert r.json()["alerts_created"] == 0

    def test_evaluate_failure_does_not_break_ingest(self, monkeypatch):
        from scry.api import router as router_mod

        self._patch_ingest(monkeypatch)

        def _boom(self):
            raise RuntimeError("db exploded")

        monkeypatch.setattr(router_mod.AlertEngine, "evaluate", _boom)
        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/ingest/run")
        assert r.status_code == 200
        assert r.json()["articles"] == 2


class TestAlertsPageChannels:
    def test_shows_channel_status(self, monkeypatch):
        monkeypatch.setenv("CTI_SLACK_WEBHOOK_URL", SLACK)
        get_settings.cache_clear()
        from scry.main import app

        with TestClient(app) as client:
            r = client.get("/ui/alerts")
        assert r.status_code == 200
        assert "Notification channels" in r.text
        assert "configured" in r.text
        assert "missing" in r.text

    def test_shows_enabled_badge(self, monkeypatch):
        monkeypatch.setenv("CTI_ENABLE_OUTBOUND_ALERTS", "true")
        get_settings.cache_clear()
        from scry.main import app

        with TestClient(app) as client:
            r = client.get("/ui/alerts")
        assert "enabled" in r.text
