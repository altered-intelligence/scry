"""Alert delivery channels (Slack/Teams/webhook/email/desktop).

Every channel is optional: a channel only fires when its settings are
configured and CTI_ENABLE_OUTBOUND_ALERTS=true. Channel failures are logged
and never block the other channels.
"""

from __future__ import annotations

import json
import smtplib
import subprocess
import sys
from contextlib import suppress
from email.message import EmailMessage

import httpx

from scry.config import Settings, get_settings
from scry.logging import get_logger
from scry.models import Alert

logger = get_logger("alerting.channels")

CHANNEL_NAMES = ("slack", "teams", "webhook", "email", "desktop")

_TEST_TEXT = "scry test message"


def deliver(alert: Alert) -> bool:
    """Deliver an alert to every configured channel. Returns delivered_any."""
    settings = get_settings()
    if not settings.enable_outbound_alerts:
        logger.debug("outbound_alerts_disabled")
        return False
    cfg = _configured_channels(settings)
    text = _format_text(alert)
    results: dict[str, bool] = {}
    if cfg["slack"]:
        results["slack"] = _guarded(
            "slack", _post_json, settings.slack_webhook_url, {"text": text, "blocks": []}
        )
    if cfg["teams"]:
        results["teams"] = _guarded("teams", _post_json, settings.teams_webhook_url, {"text": text})
    if cfg["webhook"]:
        results["webhook"] = _guarded(
            "webhook", _post_json, settings.webhook_url, _webhook_payload(alert, text)
        )
    if cfg["email"]:
        results["email"] = _guarded(
            "email", _send_email, settings, f"[scry] {alert.severity}: {alert.title}", text
        )
    if cfg["desktop"]:
        results["desktop"] = _guarded("desktop", _notify_desktop, alert.title, text)
    return any(results.values())


def deliver_test() -> dict[str, bool]:
    """Send a fixed test message through every configured channel.

    Returns a per-channel success dict with one entry per configured channel
    only. Empty dict when outbound alerts are disabled.
    """
    settings = get_settings()
    if not settings.enable_outbound_alerts:
        logger.debug("outbound_alerts_disabled")
        return {}
    cfg = _configured_channels(settings)
    results: dict[str, bool] = {}
    if cfg["slack"]:
        results["slack"] = _guarded("slack", _post_json, settings.slack_webhook_url, {"text": _TEST_TEXT})
    if cfg["teams"]:
        results["teams"] = _guarded("teams", _post_json, settings.teams_webhook_url, {"text": _TEST_TEXT})
    if cfg["webhook"]:
        results["webhook"] = _guarded("webhook", _post_json, settings.webhook_url, {"text": _TEST_TEXT})
    if cfg["email"]:
        results["email"] = _guarded("email", _send_email, settings, "[scry] test", _TEST_TEXT)
    if cfg["desktop"]:
        results["desktop"] = _guarded("desktop", _notify_desktop, "scry test", _TEST_TEXT)
    return results


def channel_status() -> dict[str, str]:
    """Per-channel 'configured'/'missing' state for the settings UI."""
    cfg = _configured_channels(get_settings())
    return {name: ("configured" if cfg[name] else "missing") for name in CHANNEL_NAMES}


def _configured_channels(settings: Settings) -> dict[str, bool]:
    email_ok = bool(settings.alert_email_from and settings.alert_email_to and settings.smtp_host)
    return {
        "slack": bool(settings.slack_webhook_url),
        "teams": bool(settings.teams_webhook_url),
        "webhook": bool(settings.webhook_url),
        "email": email_ok,
        "desktop": bool(settings.notify_desktop and sys.platform == "darwin"),
    }


def _guarded(channel: str, fn, *args) -> bool:
    """Run one channel delivery, isolating failures from the rest."""
    try:
        return bool(fn(*args))
    except Exception as exc:
        logger.warning("channel_delivery_failed", channel=channel, exc=str(exc))
        return False


def _post_json(url: str, payload: dict) -> bool:
    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(url, content=json.dumps(payload), headers={"Content-Type": "application/json"})
            r.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.warning("channel_post_failed", url=url, exc=str(exc))
        return False


def _webhook_payload(alert: Alert, text: str) -> dict:
    return {
        "text": text,
        "alert": {
            "title": alert.title,
            "severity": alert.severity,
            "why_it_matters": alert.why_it_matters,
            "recommended_action": alert.recommended_action,
            "related": alert.related,
        },
    }


def _send_email(settings: Settings, subject: str, body: str) -> bool:
    msg = EmailMessage()
    msg["From"] = settings.alert_email_from
    msg["To"] = settings.alert_email_to
    msg["Subject"] = subject
    msg.set_content(body)
    if settings.smtp_port == 465:
        smtp: smtplib.SMTP = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=15)
    else:
        smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
        if settings.smtp_starttls:
            smtp.starttls()
    try:
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(msg)
        return True
    finally:
        with suppress(smtplib.SMTPException):
            smtp.quit()


def _notify_desktop(title: str, text: str) -> bool:
    if sys.platform != "darwin":
        return False
    script = f"display notification {json.dumps(text[:200])} with title {json.dumps(title[:200])}"
    r = subprocess.run(["osascript", "-e", script], capture_output=True, timeout=10)
    return r.returncode == 0


def _format_text(alert: Alert) -> str:
    return (
        f"*{alert.title}*\n"
        f"Severity: {alert.severity}\n"
        f"Why it matters: {alert.why_it_matters or '-'}\n"
        f"Recommended action: {alert.recommended_action or '-'}\n"
    )
