"""Auth for the REST routers: optional master key + user-account sessions.

v0.4.0 behavior (unchanged): when ``CTI_API_KEY`` is set, every route on the
API routers requires the key via the ``X-API-Key`` header or an
``Authorization: Bearer <key>`` header. When the setting is empty (the
default) and no user accounts exist, everything stays open.

v0.5.0 addition: once ANY user account exists, ``/api/*`` requires auth even
without a master key — a valid ``scry_session`` cookie (browser/UI fetch
calls) or a per-user API key (plug-in hook, step 3) also satisfies it. With
zero users the API stays fully open, preserving legacy behavior for the MCP
server and local automations.

Exemptions: a small set of GET routes stays unauthenticated even when auth
is enabled, so monitoring probes and the Search-page provider picker keep
working (read-only only — mutations on the same paths require auth):

- ``/api/health`` / ``/health`` — health probe (mounted without prefix)
- ``/api/ai/status``, ``/api/ai/provider`` — Search-page provider picker

The HTML UI routes (``/ui/*`` and the dashboard) are gated by middleware in
``scry/main.py``, not through this dependency.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

# Read-only methods that may be answered without credentials on the exempt
# paths below. Everything else (PUT/POST/DELETE/PATCH/…) requires auth —
# e.g. PUT /api/ai/provider mutates stored LLM credentials and must never be
# reachable anonymously.
_UNAUTHENTICATED_METHODS = frozenset({"GET", "HEAD"})

# Routes allowed without a key even when auth is enabled (read-only methods
# only). ``/health`` covers the api_router mount (no prefix); ``/api/health``
# is kept for symmetry in case the router is ever mounted under /api.
_UNAUTHENTICATED_PATHS = frozenset(
    {
        "/api/health",
        "/health",
        "/api/ai/status",
        "/api/ai/provider",
    }
)


def _provided_key(request: Request) -> str | None:
    provided = request.headers.get("x-api-key")
    auth_header = request.headers.get("authorization")
    if not provided and auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            provided = token.strip()
    return provided


def require_api_key(request: Request) -> None:
    """FastAPI dependency enforcing API auth.

    Settings and the user table are read lazily per request (local imports)
    so tests and runtime config changes take effect without re-importing.
    """
    if request.url.path in _UNAUTHENTICATED_PATHS and request.method in _UNAUTHENTICATED_METHODS:
        return

    from scry.auth.dependencies import current_user, validate_user_api_key
    from scry.auth.sessions import users_exist
    from scry.db import session_scope

    with session_scope() as session:
        has_users = users_exist(session)

    if has_users:
        # Browser/UI fetch calls carry the session cookie; per-user API keys
        # plug in via validate_user_api_key (step 3). The resolved user is
        # stashed on request.state so endpoints (chat privacy) can apply
        # per-user rules without re-validating.
        user = current_user(request)
        if user is not None:
            request.state.api_user = user
            return
        user = validate_user_api_key(request)
        if user is not None:
            request.state.api_user = user
            return

    from scry.config import get_settings

    expected = get_settings().api_key
    if not expected:
        if has_users:
            # Accounts exist but no credentials were presented — auth is on.
            raise HTTPException(
                status_code=401,
                detail="Authentication required (session cookie, user API key, or master key)",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return  # no users and no master key — open by default (legacy behavior)

    provided = _provided_key(request)
    if provided is not None and hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8")):
        return

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
