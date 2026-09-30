"""WebAuthn passkey helpers (v0.5.0 step 5).

Passkeys are registered per user on /profile and used for username-first
sign-in at /login. The relying party is derived PER REQUEST from the Host
header so the same deployment works on http://localhost immediately and on
LAN + HTTPS later:

- ``rp_id`` = Host with any port stripped (``localhost:7100`` → ``localhost``,
  ``scry.lan:8443`` → ``scry.lan``, bracketed IPv6 keeps its colons);
- ``origin`` = request URL scheme + ``://`` + Host.

The in-flight ceremony challenge rides in a short-lived Fernet-encrypted
pending cookie (same pattern as the MFA pending marker): register-*/login
passkey begin issues it, complete consumes it. ``verify_registration_response``
and ``verify_authentication_response`` are module-level imports (not wrapped)
so tests can monkeypatch them at the ``scry.auth.webauthn`` boundary.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from fastapi import Request
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from scry.crypto import decrypt, encrypt
from scry.models import PasskeyCredential, User

# ``verify_*`` are re-exported as module attributes so routes call them as
# ``_webauthn.verify_…`` and tests can monkeypatch them at this boundary.
__all__ = [
    "PASSKEY_PENDING_COOKIE",
    "PASSKEY_PENDING_TTL",
    "RP_NAME",
    "authentication_options_json",
    "challenge_bytes",
    "credential_id_bytes",
    "issue_passkey_marker",
    "read_passkey_marker",
    "registration_options_json",
    "rp_context",
    "rp_id_from_host",
    "verify_authentication_response",
    "verify_registration_response",
]

RP_NAME = "Scry"
PASSKEY_PENDING_COOKIE = "scry_passkey_pending"
PASSKEY_PENDING_TTL = timedelta(minutes=5)


def rp_id_from_host(host: str) -> str:
    """Host header → relying-party ID (port stripped, IPv6-safe)."""
    host = (host or "").strip()
    if not host:
        return "localhost"
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if ":" in host else host


def rp_context(request: Request) -> tuple[str, str]:
    """(rp_id, origin) derived per-request from Host + URL scheme."""
    host = request.headers.get("host", "")
    return rp_id_from_host(host), f"{request.url.scheme}://{host}"


def registration_options_json(
    user: User, credentials: list[PasskeyCredential], rp_id: str
) -> tuple[str, str]:
    """Registration options for ``user``; returns (options_json, challenge_b64).

    Existing credentials are excluded so the authenticator does not register
    the same passkey twice. The user handle is the user id as bytes.
    """
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_name=user.username,
        user_display_name=user.display_name or user.username,
        user_id=str(user.id).encode("utf-8"),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in credentials] or None,
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def authentication_options_json(credentials: list[PasskeyCredential], rp_id: str) -> tuple[str, str]:
    """Assertion options restricted to ``credentials``; returns (json, challenge_b64)."""
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c.credential_id) for c in credentials] or None,
    )
    return options_to_json(options), bytes_to_base64url(options.challenge)


def challenge_bytes(challenge_b64: str) -> bytes:
    return base64url_to_bytes(challenge_b64)


def credential_id_bytes(credential: dict) -> bytes | None:
    """Raw CBOR credential id from the browser's JSON (rawId preferred)."""
    raw = credential.get("rawId") or credential.get("id")
    if not raw:
        return None
    try:
        return base64url_to_bytes(raw)
    except Exception:
        return None


# ------------------------- pending ceremony marker -------------------------


def issue_passkey_marker(user_id: int, challenge_b64: str, now: datetime | None = None) -> str:
    """Fernet-encrypted ``{"uid", "exp", "challenge"}`` for the pending cookie."""
    now = now or datetime.now(UTC)
    payload = {
        "uid": user_id,
        "exp": (now + PASSKEY_PENDING_TTL).timestamp(),
        "challenge": challenge_b64,
    }
    return encrypt(json.dumps(payload))


def read_passkey_marker(token: str | None, now: datetime | None = None) -> dict | None:
    """Resolve a pending marker to ``{"uid": int, "challenge": str}`` or None."""
    if not token:
        return None
    try:
        payload = json.loads(decrypt(token))
        uid, exp, challenge = int(payload["uid"]), float(payload["exp"]), str(payload["challenge"])
    except (ValueError, TypeError, KeyError):
        return None
    now = now or datetime.now(UTC)
    if exp <= now.timestamp():
        return None
    return {"uid": uid, "challenge": challenge}
