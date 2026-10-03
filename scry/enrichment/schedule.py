"""Scheduled external enrichment (v0.15.0).

Admins configure a daily, resumable external-enrichment pass on /admin:
which providers run (only keyed+enabled ones actually fire), per-provider
time budgets, and an on/off toggle. The pass itself is executed by
``scripts/enrichment_runner.py`` — either from a system cron / scheduled
agent job, or by hand:

    python scripts/enrichment_runner.py

Settings live in ``system_settings`` under the ``enrichment.schedule.*``
prefix; last-run statistics under ``enrichment.schedule.last_run``.

Progress is tracked per provider via ``enrichment.schedule.progress.<tag>``
(last processed observable id) so interrupted passes resume where they
left off; staleness markers (``{provider}_checked_at`` + refresh TTLs)
already make re-runs cheap for completed records.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import SystemSetting

PREFIX = "enrichment.schedule."
PROGRESS_PREFIX = "enrichment.schedule.progress."
LAST_RUN_KEY = "enrichment.schedule.last_run"

ALL_PROVIDERS = ["virustotal", "otx", "fortiguard", "greynoise", "abuseipdb"]
DEFAULT_PROVIDERS = ["otx", "fortiguard", "virustotal"]

DEFAULT_OTX_BUDGET_SECONDS = 240
DEFAULT_VT_BUDGET_SECONDS = 240
MIN_BUDGET = 30
MAX_BUDGET = 3600


@dataclass
class EnrichmentSchedule:
    """Effective schedule config (defaults when nothing is stored)."""

    enabled: bool = True
    providers: list[str] = field(default_factory=lambda: list(DEFAULT_PROVIDERS))
    otx_budget_seconds: int = DEFAULT_OTX_BUDGET_SECONDS
    vt_budget_seconds: int = DEFAULT_VT_BUDGET_SECONDS
    last_run_at: str = ""
    last_run_summary: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "providers": list(self.providers),
            "otx_budget_seconds": self.otx_budget_seconds,
            "vt_budget_seconds": self.vt_budget_seconds,
            "last_run_at": self.last_run_at,
            "last_run_summary": dict(self.last_run_summary),
        }


def _get(session: Session, key: str) -> str:
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == key))
    return (row.value or "") if row else ""


def _set(session: Session, key: str, value: str) -> None:
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == key))
    if row is None:
        session.add(SystemSetting(key=key, value=value))
    else:
        row.value = value
    session.flush()


def _clamp_budget(value: Any, default: int) -> int:
    try:
        return max(MIN_BUDGET, min(MAX_BUDGET, int(value)))
    except (TypeError, ValueError):
        return default


def get_schedule(session: Session) -> EnrichmentSchedule:
    """Effective schedule config; stored values win, defaults otherwise."""
    sched = EnrichmentSchedule()
    enabled_raw = _get(session, PREFIX + "enabled").strip().lower()
    if enabled_raw:
        sched.enabled = enabled_raw == "true"
    providers_raw = _get(session, PREFIX + "providers").strip().lower()
    if providers_raw:
        sched.providers = [p for p in (x.strip() for x in providers_raw.split(",")) if p in ALL_PROVIDERS]
    sched.otx_budget_seconds = _clamp_budget(
        _get(session, PREFIX + "otx_budget_seconds"), DEFAULT_OTX_BUDGET_SECONDS
    )
    sched.vt_budget_seconds = _clamp_budget(
        _get(session, PREFIX + "vt_budget_seconds"), DEFAULT_VT_BUDGET_SECONDS
    )
    last_run_raw = _get(session, LAST_RUN_KEY)
    if last_run_raw:
        try:
            payload = json.loads(last_run_raw)
            sched.last_run_at = str(payload.get("at") or "")
            summary = payload.get("summary")
            if isinstance(summary, dict):
                sched.last_run_summary = summary
        except (TypeError, ValueError):
            pass
    return sched


def save_schedule(
    session: Session,
    *,
    enabled: bool,
    providers: list[str],
    otx_budget_seconds: int,
    vt_budget_seconds: int,
) -> EnrichmentSchedule:
    """Validate and persist the schedule (admins only at the route layer).

    The caller writes the audit record (``enrichment_schedule.update``).
    """
    clean = [p for p in dict.fromkeys(providers) if p in ALL_PROVIDERS]
    _set(session, PREFIX + "enabled", "true" if enabled else "false")
    _set(session, PREFIX + "providers", ",".join(clean))
    _set(
        session,
        PREFIX + "otx_budget_seconds",
        str(_clamp_budget(otx_budget_seconds, DEFAULT_OTX_BUDGET_SECONDS)),
    )
    _set(
        session,
        PREFIX + "vt_budget_seconds",
        str(_clamp_budget(vt_budget_seconds, DEFAULT_VT_BUDGET_SECONDS)),
    )
    return get_schedule(session)


def get_progress(session: Session, tag: str) -> int:
    """Last processed observable id for a provider pass (0 = start fresh)."""
    raw = _get(session, PROGRESS_PREFIX + tag).strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def set_progress(session: Session, tag: str, last_id: int) -> None:
    _set(session, PROGRESS_PREFIX + tag, str(max(0, int(last_id))))


def record_last_run(session: Session, summary: dict[str, Any]) -> None:
    """Persist when the pass ran and its per-provider counters."""
    payload = {"at": datetime.now(UTC).isoformat(), "summary": summary}
    _set(session, LAST_RUN_KEY, json.dumps(payload, default=str))
