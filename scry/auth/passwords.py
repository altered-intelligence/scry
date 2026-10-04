"""bcrypt password hashing (v0.5.0 step 1).

bcrypt handles per-user salts internally; 12 rounds is the current OWASP
recommendation for password storage.

bcrypt only reads the first 72 bytes of its input: bcrypt >= 5 refuses longer
passwords outright (``ValueError``) and older releases silently truncated them
(so two passwords sharing their first 72 bytes were interchangeable). Passwords
that fit are hashed exactly as before — every existing hash keeps verifying.
Longer passphrases are supported by pre-hashing: the stored value is
``bcrypt-sha256$`` followed by a bcrypt hash of ``base64(sha256(password))``
(a fixed 44 bytes, so the whole password counts). ``MAX_PASSWORD_CHARS`` bounds
input size.
"""

from __future__ import annotations

import base64
import hashlib

import bcrypt

BCRYPT_ROUNDS = 12

BCRYPT_MAX_BYTES = 72  # bcrypt ignores (or, in 5.x, rejects) anything beyond this
MAX_PASSWORD_CHARS = 1024
_PREHASH_PREFIX = "bcrypt-sha256$"


class PasswordTooLongError(ValueError):
    """Password exceeds ``MAX_PASSWORD_CHARS``."""


def password_length_error(password: str) -> str | None:
    """User-facing message when ``password`` is too long, else None."""
    if len(password or "") > MAX_PASSWORD_CHARS:
        return f"Password must be at most {MAX_PASSWORD_CHARS:,} characters."
    return None


def _prehash(password: str) -> bytes:
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    if len(password) > MAX_PASSWORD_CHARS:
        raise PasswordTooLongError(password_length_error(password))
    data = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    if len(data) <= BCRYPT_MAX_BYTES:
        return bcrypt.hashpw(data, salt).decode("ascii")  # unchanged legacy format
    return _PREHASH_PREFIX + bcrypt.hashpw(_prehash(password), salt).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    if len(password) > MAX_PASSWORD_CHARS:
        return False
    try:
        if password_hash.startswith(_PREHASH_PREFIX):
            return bcrypt.checkpw(_prehash(password), password_hash[len(_PREHASH_PREFIX) :].encode("ascii"))
        data = password.encode("utf-8")
        if len(data) > BCRYPT_MAX_BYTES:
            return False  # a plain bcrypt hash can only come from a password that fit
        return bcrypt.checkpw(data, password_hash.encode("ascii"))
    except ValueError:
        return False
