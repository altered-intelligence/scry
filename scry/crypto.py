"""Symmetric encryption helper for storing secrets (API keys) at rest.

The Fernet key lives at ``.cti_secret`` in the project root and is auto-generated
on first use. Add ``.cti_secret`` to ``.gitignore`` — it must NEVER be checked in.
Set ``CTI_SECRET_FILE`` to relocate the key (containers, read-only installs).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_log = logging.getLogger(__name__)

_HERE = Path(__file__).resolve().parent.parent
_SECRET_PATH = _HERE / ".cti_secret"


def _secret_path() -> Path:
    """Resolve the key file location at call time.

    ``CTI_SECRET_FILE`` wins when set — installed/container deployments put the
    package in read-only site-packages, where the default path is unwritable.
    Tests may still monkeypatch the ``_SECRET_PATH`` fallback directly.
    """
    override = os.environ.get("CTI_SECRET_FILE")
    return Path(override) if override else _SECRET_PATH


def _get_key() -> bytes:
    """Load or generate the Fernet key."""
    path = _secret_path()
    if path.exists():
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError as exc:
        _log.warning("cti_secret_chmod_failed: %s — key file may be world-readable", exc)
    return key


def get_fernet() -> Fernet:
    return Fernet(_get_key())


def encrypt(plaintext: str) -> str:
    """Encrypt a string (e.g. API key) for storage in the DB."""
    if plaintext is None:
        return ""
    return get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str | None) -> str:
    """Decrypt a ciphertext from the DB. Returns empty string on failure."""
    if not ciphertext:
        return ""
    try:
        return get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def mask(secret: str, show: int = 4) -> str:
    """Show only the last N chars; mask the rest. Returns '—' if empty."""
    if not secret:
        return "—"
    if len(secret) <= show:
        return "•" * len(secret)
    return "•" * (len(secret) - show) + secret[-show:]
