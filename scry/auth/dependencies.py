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
_PROTECTED_UI_PREFIXES = ("/ui", "/admin")


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
    """Per-user API key hook — implemented in v0.5.0 step 3.

    Accepts the request and returns the owning User when a valid per-user
    key is presented; returns None otherwise. Always None this step.
    """
    return None
