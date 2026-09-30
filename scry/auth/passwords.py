"""bcrypt password hashing (v0.5.0 step 1).

bcrypt handles per-user salts internally; 12 rounds is the current OWASP
recommendation for password storage.
"""

from __future__ import annotations

import bcrypt

BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False
