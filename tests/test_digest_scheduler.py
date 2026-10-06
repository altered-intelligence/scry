"""Daily digest email job + launchd LaunchAgent management tests.

No real SMTP, no real ~/Library — mail is monkeypatched and the LaunchAgents
directory is injected.
"""

from __future__ import annotations

import plistlib
import re

import pytest

import scry.scheduler as sched_mod
from scry import scheduler_agent
from scry.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _fresh_settings(monkeypatch):
    """No ambient digest/SMTP env from the developer's shell or .env."""
    for var in (
        "CTI_DIGEST_EMAIL_ENABLED",
        "CTI_DIGEST_EMAIL_TO",
        "CTI_DIGEST_EMAIL_HOUR",
        "CTI_SMTP_HOST",
    ):
        monkeypatch.delenv(var, raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _enable_digest(monkeypatch, to: str = "analyst@example.com") -> None:
    monkeypatch.setenv("CTI_DIGEST_EMAIL_ENABLED", "true")
    monkeypatch.setenv("CTI_DIGEST_EMAIL_TO", to)
    get_settings.cache_clear()


# ------------------------- digest job -------------------------


class TestDigestJob:
    def test_disabled_skips_before_touching_smtp(self, session, monkeypatch):
        called = []
        monkeypatch.setattr(sched_mod, "send_mail", lambda *a, **k: called.append(a) or True)
        sched_mod._digest_job()
        assert called == []

    def test_smtp_unconfigured_skips_cleanly(self, session, monkeypatch):
        _enable_digest(monkeypatch)
        monkeypatch.setattr(sched_mod, "smtp_configured", lambda s: False)
        sent = []
        monkeypatch.setattr(sched_mod, "send_mail", lambda *a, **k: sent.append(k) or True)
        sched_mod._digest_job()  # must not raise
        assert sent == []

    def test_enabled_and_configured_sends_report(self, session, monkeypatch):
        _enable_digest(monkeypatch)
        monkeypatch.setattr(sched_mod, "smtp_configured", lambda s: True)
        captured = {}

        def _fake_send(sess, subject, body, to, from_address=None, markdown_body=None):
            captured.update(subject=subject, body=body, to=to, markdown_body=markdown_body)
            return True

        monkeypatch.setattr(sched_mod, "send_mail", _fake_send)
        sched_mod._digest_job()
        assert captured["to"] == "analyst@example.com"
        assert captured["subject"].startswith("Scry daily digest — ")
        assert "articles, " in captured["subject"] and "high-risk)" in captured["subject"]
        assert "# Scry Daily Threat Brief" in captured["body"]
        assert captured["markdown_body"] == captured["body"]  # plain + markdown parts

    def test_empty_recipient_skips(self, session, monkeypatch):
        monkeypatch.setenv("CTI_DIGEST_EMAIL_ENABLED", "true")
        monkeypatch.setenv("CTI_DIGEST_EMAIL_TO", "")
        get_settings.cache_clear()
        called = []
        monkeypatch.setattr(sched_mod, "send_mail", lambda *a, **k: called.append(a) or True)
        sched_mod._digest_job()
        assert called == []

    def test_report_failure_never_raises(self, session, monkeypatch):
        _enable_digest(monkeypatch)
        monkeypatch.setattr(sched_mod, "smtp_configured", lambda s: True)
        monkeypatch.setattr(
            sched_mod, "generate_daily_report", lambda s: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        sched_mod._digest_job()  # logged, swallowed


class TestJobRegistration:
    def test_digest_job_registered_only_when_enabled(self):
        off = _build(digest_email_enabled=False, digest_email_to="a@b.c")
        assert "digest_email" not in {j.id for j in off.get_jobs()}
        no_addr = _build(digest_email_enabled=True, digest_email_to="")
        assert "digest_email" not in {j.id for j in no_addr.get_jobs()}
        on = _build(digest_email_enabled=True, digest_email_to="a@b.c")
        assert "digest_email" in {j.id for j in on.get_jobs()}
        # Core jobs are always present either way.
        assert {"ingest_all", "otx_pulses", "alerts", "cluster", "decay"} <= {j.id for j in off.get_jobs()}

    def test_digest_hour_is_clamped(self):
        s = _build(digest_email_enabled=True, digest_email_to="a@b.c", digest_email_hour=99)
        job = next(j for j in s.get_jobs() if j.id == "digest_email")
        assert "hour='23'" in str(job.trigger)


def _build(**overrides):
    kwargs = {"digest_email_enabled": False, **overrides}
    return sched_mod._build_scheduler(Settings(**kwargs))


# ------------------------- launchd agent -------------------------


class TestLaunchAgent:
    def test_install_writes_correct_plist(self, tmp_path):
        res = scheduler_agent.install(agents_dir=tmp_path)
        assert res.action == "installed"
        data = plistlib.loads(res.plist_path.read_bytes())
        assert data["Label"] == scheduler_agent.LABEL
        args = data["ProgramArguments"]
        assert re.search(r"python[\d.]*$", args[0]) and args[1:] == ["-m", "scry.scheduler"]
        assert data["WorkingDirectory"] == str(scheduler_agent.REPO_ROOT)
        db_url = data["EnvironmentVariables"]["CTI_DATABASE_URL"]
        assert db_url.startswith("sqlite+pysqlite:///")
        assert "/./" not in db_url  # absolute path, anchored at the repo
        assert data["RunAtLoad"] is True and data["KeepAlive"] is True
        assert data["StandardOutPath"].endswith("logs/scheduler.log")
        assert data["StandardErrorPath"].endswith("logs/scheduler.err.log")

    def test_install_is_idempotent(self, tmp_path):
        first = scheduler_agent.install(agents_dir=tmp_path)
        second = scheduler_agent.install(agents_dir=tmp_path)
        assert second.action == "unchanged"
        assert first.plist_path.read_bytes() == second.plist_path.read_bytes()

    def test_uninstall_removes_plist(self, tmp_path):
        scheduler_agent.install(agents_dir=tmp_path)
        removed = scheduler_agent.uninstall(agents_dir=tmp_path)
        assert removed is not None and not removed.exists()
        assert scheduler_agent.uninstall(agents_dir=tmp_path) is None

    def test_status_reflects_install_state(self, tmp_path):
        st = scheduler_agent.status(agents_dir=tmp_path)
        assert st["installed"] is False
        scheduler_agent.install(agents_dir=tmp_path)
        st = scheduler_agent.status(agents_dir=tmp_path)
        assert st["installed"] is True
        assert st["label"] == scheduler_agent.LABEL
        assert "digest_email_enabled" in st


# ------------------------- mail markdown part -------------------------


class TestMailMarkdown:
    def test_send_mail_adds_markdown_alternative(self, session, monkeypatch):
        from scry import mail as mail_mod

        monkeypatch.setenv("CTI_SMTP_HOST", "smtp.example.com")
        get_settings.cache_clear()
        captured = {}
        monkeypatch.setattr(mail_mod, "_deliver", lambda cfg, msg: captured.update(msg=msg))
        ok = mail_mod.send_mail(session, "s", "plain body", "a@b.c", markdown_body="# md body")
        assert ok is True
        msg = captured["msg"]
        assert msg.is_multipart()
        parts = {p.get_content_type(): p.get_content() for p in msg.iter_parts()}
        assert parts["text/plain"] == "plain body\n"
        assert parts["text/markdown"] == "# md body\n"
