"""Shared rate-limit bookkeeping for external enrichment providers.

VT's public tier is limited per-minute AND per-day; the per-minute side is
handled by the token bucket inside ``virustotal.py``. Daily quotas reset at
UTC midnight and are tracked here with an in-memory counter (cheap, and a
server restart only "forgets" a partially used day — quota is never exceeded
because each consume() is checked before the HTTP call).
"""

from __future__ import annotations

from datetime import UTC, datetime


class DailyQuota:
    """In-memory per-day call budget. Not thread-safe by design — the
    enrichment batch is single-threaded; keep it simple."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, limit)
        self._day = ""
        self._count = 0

    def consume(self) -> bool:
        """Take one slot; False when the daily budget is exhausted."""
        today = datetime.now(UTC).date().isoformat()
        if today != self._day:
            self._day = today
            self._count = 0
        if self._count >= self.limit:
            return False
        self._count += 1
        return True

    @property
    def used(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self._count)
