"""Per-user personal threat-feed API keys (v0.5.0 step 6).

Key-resolution rule (locked in FEATURES.md):
- Background / scheduled ingest+enrichment uses the SYSTEM keys (env/DB
  chain via ``connector_settings``) — unchanged.
- User-triggered enrichment (manual run, live lookup, key test, bulk
  "enrich unenriched") uses the ACTING USER's personal VT/OTX keys.
- A user without a personal key for a provider cannot run that provider
  (it is skipped with reason "no personal key") but sees all shared
  enriched data, since results land in the common ``observables``
  enrichment JSON either way.

Keys are stored Fernet-encrypted (``scry.crypto``); one row per
(user_id, provider), upserted in code. Key material is NEVER written to
logs or error strings — ``test_key`` sanitizes every error message.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.crypto import decrypt, encrypt
from scry.models import UserFeedKey

VT_USER_URL = "https://www.virustotal.com/api/v3/users/current"
OTX_USER_URL = "https://otx.alienvault.com/api/v1/users/me"
# FortiGuard has no "whoami" endpoint — the authenticated check is a known-live
# indicator lookup (200 = found, 404 = auth OK but indicator unknown; both fine).
FG_TEST_URL = "https://ioc-api.fortiguard.com/v1/threat_intel_search"

_PROVIDER_TEST_URL = {
    "virustotal": VT_USER_URL,
    "otx": OTX_USER_URL,
    "fortiguard": FG_TEST_URL,
}


def validate_provider(provider: str) -> str:
    if provider not in UserFeedKey.PROVIDERS:
        raise ValueError(
            f"Unknown personal-key provider {provider!r}. " f"Supported: {', '.join(UserFeedKey.PROVIDERS)}"
        )
    return provider


def get_key(session: Session, user_id: int, provider: str) -> UserFeedKey | None:
    """The stored key row for (user, provider), or None."""
    validate_provider(provider)
    return session.scalar(
        select(UserFeedKey).where(UserFeedKey.user_id == user_id, UserFeedKey.provider == provider)
    )


def get_decrypted_key(session: Session, user_id: int, provider: str) -> str:
    """Plaintext personal key for (user, provider); "" when not set."""
    row = get_key(session, user_id, provider)
    return decrypt(row.api_key_encrypted) if row else ""


def keys_for_user(session: Session, user_id: int) -> dict[str, str]:
    """Decrypted personal keys {provider: key} for every provider the user has."""
    rows = session.scalars(select(UserFeedKey).where(UserFeedKey.user_id == user_id)).all()
    out: dict[str, str] = {}
    for r in rows:
        key = decrypt(r.api_key_encrypted)
        if key:
            out[r.provider] = key
    return out


def set_key(session: Session, user_id: int, provider: str, api_key: str) -> UserFeedKey:
    """Store (upsert) a personal key, encrypted at rest. One row per (user, provider)."""
    validate_provider(provider)
    api_key = (api_key or "").strip()
    if not api_key:
        raise ValueError("api_key must not be empty")
    row = session.scalar(
        select(UserFeedKey).where(UserFeedKey.user_id == user_id, UserFeedKey.provider == provider)
    )
    if row is None:
        row = UserFeedKey(user_id=user_id, provider=provider, api_key_encrypted=encrypt(api_key))
        session.add(row)
    else:
        row.api_key_encrypted = encrypt(api_key)
    session.flush()
    return row


def delete_key(session: Session, user_id: int, provider: str) -> bool:
    """Remove the personal key; returns True when a row was deleted."""
    row = get_key(session, user_id, provider)
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True


def _sanitize(message: str, api_key: str) -> str:
    """Ensure no key material can leak into a stored/logged error string."""
    if api_key:
        message = message.replace(api_key, "[redacted]")
    return message[:300]


def test_key(provider: str, api_key: str, *, timeout: float = 15.0) -> tuple[bool, str]:
    """Cheap authenticated check that a personal key works.

    VT: GET /api/v3/users/current (200 = ok). OTX: GET /api/v1/users/me
    (200 = ok). FortiGuard: GET /v1/threat_intel_search on a known-live
    sample (200 = found, 404 = auth accepted but sample not in intel — both
    count as connected). Returns (ok, error). The error is sanitized — it
    can never contain the key.
    """
    validate_provider(provider)
    if provider == "fortiguard":
        try:
            with httpx.Client(timeout=httpx.Timeout(timeout)) as client:
                r = client.get(
                    FG_TEST_URL,
                    params={"indicator": "94.100.18.64", "type": "ip"},
                    headers={"api_key": api_key, "User-Agent": "Scry/0.1"},
                )
        except httpx.HTTPError as exc:
            return False, _sanitize(f"connection error: {exc}", api_key)
        if r.status_code in (200, 404):
            return True, ""
        if r.status_code == 401:
            return False, "HTTP 401: key rejected"
        if r.status_code == 403:
            return False, "HTTP 403: key forbidden"
        if r.status_code == 429:
            return False, "HTTP 429: quota exceeded"
        return False, _sanitize(f"HTTP {r.status_code}", api_key)
    headers = {
        "virustotal": {"x-apikey": api_key, "User-Agent": "Scry/0.1"},
        "otx": {"X-OTX-API-KEY": api_key, "User-Agent": "Scry/0.1"},
    }[provider]
    try:
        with httpx.Client(timeout=httpx.Timeout(timeout)) as client:
            r = client.get(_PROVIDER_TEST_URL[provider], headers=headers)
    except httpx.HTTPError as exc:
        return False, _sanitize(f"connection error: {exc}", api_key)
    if r.status_code == 200:
        return True, ""
    if r.status_code == 401:
        return False, "HTTP 401: key rejected"
    if r.status_code == 403:
        return False, "HTTP 403: key forbidden"
    return False, _sanitize(f"HTTP {r.status_code}", api_key)


def record_test_result(session: Session, row: UserFeedKey, ok: bool, error: str) -> None:
    """Update last_test_* on the key row (call after test_key)."""
    row.last_test_at = datetime.now(UTC)
    row.last_test_ok = ok
    row.last_test_error = None if ok else (error or "test failed")
    session.flush()
