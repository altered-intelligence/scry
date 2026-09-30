"""Request-level auth helpers: session resolution + UI gating.

``current_user`` resolves the ``scry_session`` cookie against the DB (with
sliding-expiry extension) and is used by both the UI middleware and the
extended ``require_api_key`` API dependency.

``validate_user_api_key`` is the deliberate plug-in point for per-user API
keys (v0.5.0 step 3): the API dependency calls it before falling back to the
master key, so step 3 only needs to implement this one function.
"""

from __future__ import annotations

from fastapi import Request

from scry.auth.sessions import SESSION_COOKIE, users_exist, validate_session
from scry.db import session_scope
from scry.models import User

# Browser paths gated behind a session once any user exists. ``/admin`` has
# no routes yet (step 2) — the prefix is registered now so nothing leaks
# when it appears. ``/`` is the dashboard.
_PROTECTED_UI_PREFIXES = ("/ui", "/admin", "/profile")


def path_requires_ui_auth(path: str) -> bool:
    return path == "/" or path.startswith(_PROTECTED_UI_PREFIXES)


def users_exist_in_db() -> bool:
    with session_scope() as session:
        return users_exist(session)


def current_user(request: Request) -> User | None:
    """Resolve the ``scry_session`` cookie to a user (extends sliding expiry)."""
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    with session_scope() as session:
        return validate_session(session, raw)


def validate_user_api_key(request: Request) -> User | None:
    """Per-user API key hook (v0.5.0 step 3).

    Accepts ``X-API-Key: sk-…`` or ``Authorization: Bearer sk-…``, looks the
    key up by sha256, and returns the owning user when the key is active (not
    revoked, not expired, active user). ``last_used_at`` is touched at most
    once a minute so authenticated polling doesn't write on every request.
    Returns None when no valid key is presented.
    """
    provided = request.headers.get("x-api-key")
    if not provided:
        auth_header = request.headers.get("authorization")
        if auth_header:
            scheme, _, token = auth_header.partition(" ")
            if scheme.lower() == "bearer" and token.strip():
                provided = token.strip()
    if not provided:
        return None

    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from scry.auth.sessions import hash_token
    from scry.models import ApiKey

    digest = hash_token(provided)
    with session_scope() as session:
        api_key = session.scalar(select(ApiKey).where(ApiKey.key_hash == digest))
        if api_key is None:
            return None
        now = datetime.now(UTC)
        expired = False
        if api_key.expires_at is not None:
            exp = (
                api_key.expires_at
                if api_key.expires_at.tzinfo is not None
                else api_key.expires_at.replace(tzinfo=UTC)
            )
            expired = exp <= now
        if api_key.revoked_at is not None or expired:
            return None
        user = session.get(User, api_key.user_id)
        if user is None or user.status != "active":
            return None
        # Throttled last-used touch: skip the write when touched < 1 min ago.
        last_used = api_key.last_used_at
        if last_used is not None and last_used.tzinfo is None:
            last_used = last_used.replace(tzinfo=UTC)
        if last_used is None or now - last_used >= timedelta(minutes=1):
            api_key.last_used_at = now
            session.flush()
        return user
