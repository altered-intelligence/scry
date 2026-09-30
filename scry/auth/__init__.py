"""User-account auth: bcrypt passwords, DB-backed sessions, login throttling."""

from scry.auth.dependencies import current_user, path_requires_ui_auth, validate_user_api_key
from scry.auth.passwords import hash_password, verify_password
from scry.auth.sessions import (
    SESSION_COOKIE,
    SESSION_TTL,
    create_session,
    lockout_remaining,
    record_login_failure,
    record_login_success,
    revoke_all_sessions,
    revoke_session,
    users_exist,
    validate_session,
)

__all__ = [
    "SESSION_COOKIE",
    "SESSION_TTL",
    "create_session",
    "current_user",
    "hash_password",
    "lockout_remaining",
    "path_requires_ui_auth",
    "record_login_failure",
    "record_login_success",
    "revoke_all_sessions",
    "revoke_session",
    "users_exist",
    "validate_session",
    "validate_user_api_key",
    "verify_password",
]
