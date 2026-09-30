"""Optional static API-token auth for the REST routers.

When ``CTI_API_KEY`` is set, every route on the API routers requires the key
via the ``X-API-Key`` header or an ``Authorization: Bearer <key>`` header.
When the setting is empty (the default), everything stays open and behavior
is unchanged.

Exemptions: a small set of routes stays unauthenticated even when a key is
configured, so monitoring probes and the Search-page provider picker keep
working:

- ``/api/health`` / ``/health`` — health probe (mounted without prefix)
- ``/api/ai/status``, ``/api/ai/provider`` — Search-page provider picker

The HTML UI routes (``/ui/*`` and the dashboard) are plain ``@app`` routes in
``scry/main.py`` and are not wired through this dependency at all.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

# Routes allowed without a key even when auth is enabled. ``/health`` covers
# the api_router mount (no prefix); ``/api/health`` is kept for symmetry in
# case the router is ever mounted under /api.
_UNAUTHENTICATED_PATHS = frozenset(
    {
        "/api/health",
        "/health",
        "/api/ai/status",
        "/api/ai/provider",
    }
)


def require_api_key(request: Request) -> None:
    """FastAPI dependency enforcing the optional static API key.

    Settings are read lazily per request (local import) so tests and runtime
    config changes take effect without re-importing the routers.
    """
    if request.url.path in _UNAUTHENTICATED_PATHS:
        return

    from scry.config import get_settings

    expected = get_settings().api_key
    if not expected:
        return  # auth not configured — open by default (unchanged behavior)

    provided = request.headers.get("x-api-key")
    auth_header = request.headers.get("authorization")
    if not provided and auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            provided = token.strip()

    if provided is not None and hmac.compare_digest(
        provided.encode("utf-8"), expected.encode("utf-8")
    ):
        return

    raise HTTPException(
        status_code=401,
        detail="Invalid or missing API key",
        headers={"WWW-Authenticate": "Bearer"},
    )
