"""TOTP MFA helpers (v0.5.0 step 4).

Google Authenticator-compatible TOTP via pyotp (SHA-1, 30 s step, 6 digits)
plus one-time recovery codes. Secrets are stored Fernet-encrypted in
``users.totp_secret_encrypted``; recovery codes are stored as sha256 hashes
in ``recovery_codes`` and each is single-use.

Setup is verify-before-enable: a freshly generated secret sits in
``totp_pending`` state until the user proves possession with a valid code;
only then is ``totp_enabled`` set and the recovery codes issued.
"""

from __future__ import annotations

import base64
import hashlib
import io
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import RecoveryCode, User

ISSUER = "Scry"
TOTP_VALID_WINDOW = 1  # accept the previous/current/next 30 s step
MFA_PENDING_TTL = timedelta(minutes=5)
MFA_PENDING_COOKIE = "scry_mfa_pending"
MAX_MFA_ATTEMPTS = 5
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 10  # secrets.token_urlsafe(10) → ~14 chars


def generate_secret() -> str:
    import pyotp

    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str) -> str:
    """otpauth:// URI scanned by Google Authenticator et al."""
    import pyotp

    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_data_uri(uri: str, box_size: int = 6) -> str:
    """Render a QR code as a ``data:image/png;base64,...`` URI (page-lifetime
    only — no standalone QR endpoint exists, so the secret never leaks via a
    guessable URL)."""
    import qrcode

    img = qrcode.make(uri, box_size=box_size)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp(secret: str, code: str) -> bool:
    """Validate a 6-digit TOTP code against ``secret`` (±1 step tolerance)."""
    import pyotp

    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    return bool(pyotp.TOTP(secret).verify(code, valid_window=TOTP_VALID_WINDOW))


# ------------------------- recovery codes -------------------------


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def generate_recovery_codes() -> list[str]:
    return [secrets.token_urlsafe(RECOVERY_CODE_BYTES) for _ in range(RECOVERY_CODE_COUNT)]


def store_recovery_codes(session: Session, user_id: int, codes: list[str]) -> None:
    for code in codes:
        session.add(RecoveryCode(user_id=user_id, code_hash=hash_recovery_code(code)))
    session.flush()


def use_recovery_code(session: Session, user: User, code: str) -> bool:
    """Consume a recovery code: single-use (``used_at`` stamped). Returns True
    on success."""
    digest = hash_recovery_code(code)
    row = session.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == digest,
            RecoveryCode.used_at.is_(None),
        )
    )
    if row is None:
        return False
    row.used_at = datetime.now(UTC)
    session.flush()
    return True


def delete_recovery_codes(session: Session, user_id: int) -> int:
    from sqlalchemy import delete

    result = session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    session.flush()
    return int(result.rowcount or 0)


# ------------------------- login challenge (pending cookie) -------------------------


def issue_pending_marker(user_id: int, now: datetime | None = None) -> str:
    """Fernet-encrypted ``{"uid": …, "exp": …}`` for the mfa_pending cookie."""
    import json

    from scry.crypto import encrypt

    now = now or datetime.now(UTC)
    payload = {"uid": user_id, "exp": (now + MFA_PENDING_TTL).timestamp()}
    return encrypt(json.dumps(payload))


def read_pending_marker(token: str | None, now: datetime | None = None) -> int | None:
    """Resolve a pending marker to a user id, or None when missing/invalid/expired."""
    import json

    from scry.crypto import decrypt

    if not token:
        return None
    try:
        payload = json.loads(decrypt(token))
        uid, exp = int(payload["uid"]), float(payload["exp"])
    except (ValueError, TypeError, KeyError):
        return None
    now = now or datetime.now(UTC)
    if exp <= now.timestamp():
        return None
    return uid


# In-memory per-user attempt counter for the MFA challenge step (process-local,
# like a rate-limit bucket — losing it on restart only forgives attempts).
_mfa_attempts: dict[int, int] = {}


def mfa_attempt_count(user_id: int) -> int:
    return _mfa_attempts.get(user_id, 0)


def record_mfa_failure(user_id: int) -> int:
    """Bump the challenge attempt counter; returns the new count. At
    ``MAX_MFA_ATTEMPTS`` the counter resets — the caller must invalidate the
    pending marker so the user has to log in again."""
    count = _mfa_attempts.get(user_id, 0) + 1
    if count >= MAX_MFA_ATTEMPTS:
        _mfa_attempts.pop(user_id, None)
    else:
        _mfa_attempts[user_id] = count
    return count


def clear_mfa_failures(user_id: int) -> None:
    _mfa_attempts.pop(user_id, None)
