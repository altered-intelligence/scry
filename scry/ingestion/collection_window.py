"""Collection window (v0.7.0 step 2).

Only feed entries published within the last N days are collected; entries
without a date are always kept. The window is a global setting
(``collection_window_days`` in ``system_settings``, clamped to 1-7,
default 1 = last 24h) controlled by admins on /admin and displayed
read-only on the Sources page. It applies to new collection only —
existing articles are never deleted or modified.

Window semantics: an entry is kept when ``published_at >= now - N days``
(boundary inclusive); anything strictly older is skipped. Naive datetimes
are treated as UTC, matching the RSS adapter (``scry.ingestion.rss``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import SystemSetting

SETTING_KEY = "collection_window_days"
MIN_DAYS = 1
MAX_DAYS = 7
DEFAULT_DAYS = 1


def _clamp(days: int) -> int:
    return max(MIN_DAYS, min(MAX_DAYS, int(days)))


def get_window_days(session: Session) -> int:
    """Effective collection window in days (clamped 1-7, default 1 when unset)."""
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == SETTING_KEY))
    if row is None or not (row.value or "").strip():
        return DEFAULT_DAYS
    try:
        return _clamp(int(row.value.strip()))
    except ValueError:
        return DEFAULT_DAYS


def set_window_days(session: Session, days: int) -> int:
    """Validate/clamp and persist the window; returns the stored value.

    The caller writes the audit record (``collection_window.set``).
    """
    days = _clamp(days)
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == SETTING_KEY))
    if row is None:
        session.add(SystemSetting(key=SETTING_KEY, value=str(days)))
    else:
        row.value = str(days)
    session.flush()
    return days


def entry_in_window(published_at: datetime | None, days: int, now: datetime) -> bool:
    """True when the entry falls inside the collection window.

    ``None`` (feed omitted the date) always collects. The lower boundary
    is inclusive: an entry published exactly at ``now - days`` is kept,
    anything strictly older is skipped. Naive datetimes are treated as
    UTC, matching the RSS adapter.
    """
    if published_at is None:
        return True
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return published_at >= now - timedelta(days=days)
