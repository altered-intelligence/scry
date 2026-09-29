"""IOC lifecycle / decay engine.

TTLs vary by indicator type. Expired indicators stay searchable but are
not block-recommended by default.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Observable
from scry.scoring.risk import expiration_from_ttl

DEFAULT_TTLS: dict[str, int] = {
    "ipv4": 21,
    "ipv6": 21,
    "domain": 60,
    "url": 30,
    "email": 90,
    "md5": 365,
    "sha1": 365,
    "sha256": 365,
    "sha512": 365,
    "ssdeep": 365,
    "tlsh": 365,
    "registry_key": 365,
    "named_pipe": 365,
    "attack_technique": 0,  # never expires
    "cve": 0,  # never expires
    "onion": 30,
    "wallet_btc": 365,
    "wallet_eth": 365,
    "wallet_xmr": 365,
    "asn": 0,
    "telegram_handle": 90,
    "discord_invite": 30,
}

CLOUD_HOST_TTL_OVERRIDE = 5  # shared cloud IP/domain decays faster


def _as_aware(dt: datetime | None) -> datetime | None:
    """Coerce a datetime to UTC-aware. SQLite returns naive datetimes even
    though we store UTC, which breaks comparisons against an aware `now`."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


@dataclass
class DecayResult:
    expired: int
    refreshed: int


class LifecycleEngine:
    def __init__(self, session: Session) -> None:
        self.session = session

    def ttl_for(self, observable: Observable) -> int:
        base = DEFAULT_TTLS.get(observable.type, 30)
        enrichment = observable.enrichment or {}
        if enrichment.get("likely_cloud_or_cdn") and observable.type in {"ipv4", "ipv6", "domain", "url"}:
            return min(base, CLOUD_HOST_TTL_OVERRIDE)
        return base

    def apply_decay(self) -> DecayResult:
        now = datetime.now(UTC)
        expired = 0
        refreshed = 0
        for observable in self.session.scalars(select(Observable)):
            ttl = self.ttl_for(observable)
            if ttl <= 0:
                # Permanent records (CVE, attack technique). Keep active.
                observable.ttl_days = 0
                continue
            observable.ttl_days = ttl
            exp = observable.expiration_date
            if exp is None:
                last = (
                    _as_aware(observable.last_seen or observable.last_reported or observable.first_seen)
                    or now
                )
                # Expire TTL days *after* the last sighting, not at the sighting itself.
                observable.expiration_date = expiration_from_ttl(ttl, last)
            if observable.expiration_date and _as_aware(observable.expiration_date) < now:
                if observable.status != "expired":
                    observable.status = "expired"
                    observable.actionability = "monitor"
                    expired += 1
            else:
                refreshed += 1
        self.session.commit()
        return DecayResult(expired=expired, refreshed=refreshed)
