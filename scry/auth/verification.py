"""Email verification PINs (v0.5.0 step 3).

A 6-digit PIN is generated, stored as a sha256 hash with a 30-minute expiry,
and emailed via ``scry.mail`` (dormant when SMTP is unconfigured — callers
bypass verification instead, see the /profile routes). Only the newest
pending code per user is confirmable; three wrong attempts invalidate it.

``scry.mail.send_mail`` is reached through the module attribute so tests can
monkeypatch ``scry.mail.send_mail``.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import EmailVerification, User

PIN_TTL = timedelta(minutes=30)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def issue_pin(session: Session, user: User) -> str | None:
    """Create + email a fresh PIN for ``user``.

    Supersedes any still-pending codes. Returns the PIN on success, or None
    when the mail could not be sent (the pending code is then dropped).
    """
    pin = f"{secrets.randbelow(1_000_000):06d}"
    for row in session.scalars(
        select(EmailVerification).where(
            EmailVerification.user_id == user.id, EmailVerification.consumed_at.is_(None)
        )
    ):
        row.consumed_at = datetime.now(UTC)
    pending = EmailVerification(
        user_id=user.id,
        code_hash=_hash(pin),
        expires_at=datetime.now(UTC) + PIN_TTL,
    )
    session.add(pending)
    session.flush()

    from scry import mail

    body = (
        f"Hi {user.username},\n\n"
        f"Your scry verification code is: {pin}\n\n"
        "It expires in 30 minutes. If you did not request it, ignore this email.\n"
    )
    if mail.send_mail(session, "Your scry verification code", body, to=user.email):
        return pin
    session.delete(pending)
    session.flush()
    return None


def confirm_pin(session: Session, user: User, code: str) -> str:
    """Validate ``code`` against the user's newest pending PIN.

    Returns "ok", or one of: "no-code" (nothing pending), "expired",
    "invalidated" (third wrong attempt consumed the code), "mismatch".
    On success the user's email is marked verified.
    """
    row = session.scalar(
        select(EmailVerification)
        .where(
            EmailVerification.user_id == user.id,
            EmailVerification.consumed_at.is_(None),
        )
        .order_by(EmailVerification.id.desc())
    )
    if row is None:
        return "no-code"
    now = datetime.now(UTC)
    if _as_utc(row.expires_at) <= now:
        row.consumed_at = now
        session.flush()
        return "expired"
    if row.code_hash == _hash(code.strip()):
        row.consumed_at = now
        user.email_verified = True
        session.flush()
        return "ok"
    row.attempts += 1
    if row.attempts >= EmailVerification.MAX_ATTEMPTS:
        row.consumed_at = now
        session.flush()
        return "invalidated"
    session.flush()
    return "mismatch"
