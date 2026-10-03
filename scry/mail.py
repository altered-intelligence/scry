"""SMTP mailer (v0.5.0 step 2).

Sends email through the admin-configured SMTP server stored in the DB
(``system_settings`` rows with ``smtp.*`` keys, password Fernet-encrypted
via ``scry.crypto``). The env config (``config.py`` ``smtp_*`` /
``alert_email_from`` fields, v0.4.0 alert channels) remains the fallback
for every field the admin has not set.

Everything bypasses cleanly when no host is configured:
``smtp_configured()`` is False, ``send_mail()`` returns False without
attempting a connection, and ``test_smtp()`` reports the reason. Nothing
calls into this module yet except the /admin test button; later steps
(email verification PINs, password reset) reuse it.
"""

from __future__ import annotations

import smtplib
from contextlib import suppress
from dataclasses import dataclass
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.config import get_settings
from scry.crypto import decrypt, encrypt
from scry.logging import get_logger
from scry.models import SystemSetting

logger = get_logger("mail")

# system_settings keys for the admin-configured SMTP server.
SMTP_KEYS = ("host", "port", "user", "password", "starttls", "from_address")


@dataclass
class SMTPConfig:
    host: str
    port: int
    user: str
    password: str
    starttls: bool
    from_address: str


def _db_settings(session: Session) -> dict[str, str]:
    rows = session.scalars(select(SystemSetting).where(SystemSetting.key.like("smtp.%")))
    return {row.key.removeprefix("smtp."): row.value for row in rows}


def get_smtp_config(session: Session) -> SMTPConfig | None:
    """Effective SMTP config: DB-stored admin values override env fallbacks."""
    db = _db_settings(session)
    env = get_settings()
    host = (db.get("host") or "").strip() or env.smtp_host
    if not host:
        return None
    try:
        port = int((db.get("port") or "").strip() or env.smtp_port)
    except ValueError:
        port = int(env.smtp_port)
    return SMTPConfig(
        host=host,
        port=port,
        user=(db.get("user") or "").strip() or env.smtp_user,
        password=decrypt(db["password"]) if db.get("password") else env.smtp_password,
        starttls=(db.get("starttls") == "true") if "starttls" in db else env.smtp_starttls,
        from_address=(db.get("from_address") or "").strip() or env.alert_email_from,
    )


def smtp_configured(session: Session) -> bool:
    return get_smtp_config(session) is not None


def save_smtp_config(
    session: Session,
    *,
    host: str,
    port: int,
    user: str = "",
    password: str = "",
    starttls: bool = False,
    from_address: str = "",
) -> None:
    """Persist the admin SMTP config (password stored encrypted)."""
    values = {
        "host": host.strip(),
        "port": str(port),
        "user": user.strip(),
        "password": encrypt(password) if password else "",
        "starttls": "true" if starttls else "false",
        "from_address": from_address.strip(),
    }
    for key, value in values.items():
        row = session.scalar(select(SystemSetting).where(SystemSetting.key == f"smtp.{key}"))
        if row is None:
            session.add(SystemSetting(key=f"smtp.{key}", value=value))
        else:
            row.value = value
    session.flush()


def _connect(config: SMTPConfig) -> smtplib.SMTP:
    """Open the connection (STARTTLS + login when configured), mirroring channels.py."""
    if config.port == 465:
        smtp: smtplib.SMTP = smtplib.SMTP_SSL(config.host, config.port, timeout=15)
    else:
        smtp = smtplib.SMTP(config.host, config.port, timeout=15)
        if config.starttls:
            smtp.starttls()
    if config.user:
        smtp.login(config.user, config.password)
    return smtp


def _deliver(config: SMTPConfig, msg: EmailMessage) -> None:
    smtp = _connect(config)
    try:
        smtp.send_message(msg)
    finally:
        with suppress(smtplib.SMTPException):
            smtp.quit()


def send_mail(
    session: Session,
    subject: str,
    body: str,
    to: str,
    from_address: str | None = None,
    markdown_body: str | None = None,
) -> bool:
    """Send an email. Returns False (logged) when unconfigured/failing.

    Plain-text by default; with ``markdown_body`` the message becomes
    multipart/alternative (text/plain fallback + text/markdown part).
    """
    config = get_smtp_config(session)
    if config is None:
        logger.info("mail_skipped_unconfigured", subject=subject)
        return False
    sender = from_address or config.from_address
    msg = EmailMessage()
    msg["From"] = sender or config.user or config.host
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    if markdown_body is not None:
        msg.add_alternative(markdown_body, subtype="markdown")
    try:
        _deliver(config, msg)
    except Exception as exc:
        logger.warning("mail_send_failed", subject=subject, error=str(exc))
        return False
    logger.info("mail_sent", subject=subject, to=to)
    return True


def test_smtp(session: Session, to: str | None = None) -> tuple[bool, str | None]:
    """Connectivity check for the /admin test button.

    Without ``to`` this only connects (and authenticates when credentials
    are set). With ``to`` it also sends a test message to that address.
    Returns (ok, error-message-or-None).
    """
    config = get_smtp_config(session)
    if config is None:
        return False, "SMTP is not configured."
    try:
        if to:
            msg = EmailMessage()
            msg["From"] = config.from_address or config.user or config.host
            msg["To"] = to
            msg["Subject"] = "Scry SMTP test"
            msg.set_content("This is a test message from your Scry admin panel.")
            _deliver(config, msg)
        else:
            # Probe only: connect (and authenticate when credentials are set).
            smtp = _connect(config)
            with suppress(smtplib.SMTPException):
                smtp.quit()
    except Exception as exc:
        logger.warning("smtp_test_failed", error=str(exc))
        return False, str(exc)
    return True, None
