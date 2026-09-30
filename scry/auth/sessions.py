"""DB-backed session tokens + login throttling.

Sessions use a sliding 7-day expiry: every validated request refreshes
``last_seen_at`` and extends ``expires_at`` when less than 24 h remain.
Only the sha256 hash of the random cookie value is persisted.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from scry.models import SessionToken, User

SESSION_COOKIE = "scry_session"
SESSION_TTL = timedelta(days=7)
_EXTEND_THRESHOLD = timedelta(hours=24)

MAX_FAILED_LOGINS = 5
LOCKOUT = timedelta(minutes=15)


def utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def users_exist(session: Session) -> bool:
    return bool(session.scalar(select(func.count(User.id))))


def create_session(
    session: Session, user: User, ip: str | None = None, user_agent: str | None = None
) -> str:
    """Create a session for ``user``; returns the raw (cookie) token."""
    raw = secrets.token_urlsafe(32)
    session.add(
        SessionToken(
            token_hash=hash_token(raw),
            user_id=user.id,
            expires_at=utcnow() + SESSION_TTL,
            ip=ip,
            user_agent=(user_agent or "")[:512] or None,
        )
    )
    session.flush()
    return raw


def validate_session(session: Session, raw_token: str | None) -> User | None:
    """Resolve a raw cookie token to its user, extending the sliding expiry.

    Returns None for unknown, expired, or disabled-user sessions (expired
    tokens are deleted).
    """
    if not raw_token:
        return None
    token = session.scalar(
        select(SessionToken).where(SessionToken.token_hash == hash_token(raw_token))
    )
    if token is None:
        return None
    now = utcnow()
    if _as_utc(token.expires_at) <= now:
        session.delete(token)
        session.flush()
        return None
    user = session.get(User, token.user_id)
    if user is None or user.status != "active":
        return None
    token.last_seen_at = now
    if _as_utc(token.expires_at) - now < _EXTEND_THRESHOLD:
        token.expires_at = now + SESSION_TTL
    session.flush()
    return user


def revoke_session(session: Session, raw_token: str | None) -> bool:
    if not raw_token:
        return False
    result = session.execute(
        delete(SessionToken).where(SessionToken.token_hash == hash_token(raw_token))
    )
    session.flush()
    return bool(result.rowcount)


def revoke_all_sessions(session: Session, user_id: int) -> int:
    """Log out everywhere: drop every session token for a user."""
    result = session.execute(delete(SessionToken).where(SessionToken.user_id == user_id))
    session.flush()
    return int(result.rowcount or 0)


# ------------------------- login throttling -------------------------


def lockout_remaining(user: User, now: datetime | None = None) -> timedelta | None:
    """Remaining lockout time, or None when the user is not locked."""
    if user.locked_until is None:
        return None
    remaining = _as_utc(user.locked_until) - (now or utcnow())
    return remaining if remaining > timedelta(0) else None


def record_login_failure(session: Session, user: User) -> None:
    """Bump the failure counter; at ``MAX_FAILED_LOGINS`` lock for ``LOCKOUT``."""
    user.failed_login_count += 1
    if user.failed_login_count >= MAX_FAILED_LOGINS:
        user.locked_until = utcnow() + LOCKOUT
        user.failed_login_count = 0
    session.flush()


def record_login_success(session: Session, user: User) -> None:
    """Clear throttle state and stamp the successful login."""
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    session.flush()
