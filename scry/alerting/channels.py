"""Alert delivery channels (Slack/Teams/webhook/email).

Stub implementations — only post when the corresponding environment variable
is set and CTI_ENABLE_OUTBOUND_ALERTS=true. Logged and skipped otherwise.
"""

from __future__ import annotations

import json

import httpx

from scry.config import get_settings
from scry.logging import get_logger
from scry.models import Alert

logger = get_logger("alerting.channels")


def deliver(alert: Alert) -> bool:
    settings = get_settings()
    if not settings.enable_outbound_alerts:
        logger.debug("outbound_alerts_disabled")
        return False
    delivered_any = False
    if settings.slack_webhook_url:
        delivered_any |= _post_json(settings.slack_webhook_url, {"text": _format_text(alert), "blocks": []})
    if settings.teams_webhook_url:
        delivered_any |= _post_json(settings.teams_webhook_url, {"text": _format_text(alert)})
    return delivered_any


def _post_json(url: str, payload: dict) -> bool:
    try:
        with httpx.Client(timeout=10) as client:
            r = client.post(url, content=json.dumps(payload), headers={"Content-Type": "application/json"})
            r.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.warning("channel_post_failed", url=url, exc=str(exc))
        return False


def _format_text(alert: Alert) -> str:
    return (
        f"*{alert.title}*\n"
        f"Severity: {alert.severity}\n"
        f"Why it matters: {alert.why_it_matters or '-'}\n"
        f"Recommended action: {alert.recommended_action or '-'}\n"
    )
