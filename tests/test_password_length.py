"""Password length handling.

bcrypt >= 5 raises ValueError for passwords over 72 bytes. hash_password used to
crash (HTTP 500 on setup / password change / admin create, a traceback in the
CLI) while verify_password swallowed the error and returned False. Passwords
that fit keep their exact legacy hash; longer passphrases are pre-hashed.
"""

from __future__ import annotations

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from scry.auth.passwords import (
    MAX_PASSWORD_CHARS,
    PasswordTooLongError,
    hash_password,
    password_length_error,
    verify_password,
)
from scry.auth.sessions import SESSION_COOKIE
from scry.cli import app as cli_app
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import User

runner = CliRunner()
PASSWORD = "S3cure!pass"
LONG = "correct horse battery staple " * 4  # 116 bytes
MAX = "p" * MAX_PASSWORD_CHARS


class TestHashing:
    @pytest.mark.parametrize("length", [1, 71, 72])
    def test_passwords_that_fit_keep_the_legacy_format(self, length):
        pw = "a" * length
        h = hash_password(pw)
        assert h.startswith("$2") and not h.startswith("bcrypt-sha256")
        assert verify_password(pw, h)
        assert bcrypt.checkpw(pw.encode(), h.encode())  # plain bcrypt can verify it

    @pytest.mark.parametrize("length", [73, 100, 500, MAX_PASSWORD_CHARS])
    def test_longer_passwords_round_trip(self, length):
        pw = "x" * length
        h = hash_password(pw)  # used to raise ValueError
        assert h.startswith("bcrypt-sha256$") and len(h) <= 128  # fits users.password_hash
        assert verify_password(pw, h)
        assert not verify_password(pw + "y", h)
        assert not verify_password("x" * (length - 1), h)

    def test_multibyte_passwords_over_72_bytes_work(self):
        pw = "🔐" * 24  # 96 bytes, only 24 characters
        h = hash_password(pw)
        assert verify_password(pw, h) and not verify_password("🔐" * 23, h)

    def test_whole_password_counts_not_just_the_first_72_bytes(self):
        a, b = "k" * 72 + "A", "k" * 72 + "B"
        h = hash_password(a)
        assert verify_password(a, h)
        assert not verify_password(b, h)  # old bcrypt truncation would accept this

    def test_existing_legacy_hash_still_verifies(self):
        legacy = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
        assert verify_password(PASSWORD, legacy)
        assert not verify_password("wrong", legacy)

    def test_long_attempt_against_a_short_password_hash_is_false_not_a_crash(self):
        assert verify_password("z" * 200, hash_password(PASSWORD)) is False

    def test_over_the_cap_is_rejected_cleanly(self):
        too_long = "q" * (MAX_PASSWORD_CHARS + 1)
        assert password_length_error(too_long)
        assert password_length_error(MAX) is None
        with pytest.raises(PasswordTooLongError):
            hash_password(too_long)
        assert verify_password(too_long, hash_password(PASSWORD)) is False

    def test_garbage_hash_is_false(self):
        assert verify_password("x", "not-a-hash") is False
        assert verify_password("x", "bcrypt-sha256$not-a-hash") is False


def _make_user(username="alice", password=PASSWORD, role="user"):
    with session_scope() as s:
        s.add(
            User(
                username=username,
                email=f"{username}@example.com",
                role=role,
                password_hash=hash_password(password),
            )
        )


def _get_user(username):
    with session_scope() as s:
        return s.scalar(select(User).where(func.lower(User.username) == username.lower()))


def _login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def _csrf(client):
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


class TestRoutes:
    def test_login_with_a_long_password_works_end_to_end(self):
        _make_user("bob", LONG)
        client = TestClient(app)
        r = _login(client, "bob", LONG)
        assert r.status_code == 303 and r.headers["location"] == "/"
        assert SESSION_COOKIE in client.cookies

    def test_login_attempt_with_oversized_password_is_a_clean_failure(self):
        _make_user()
        client = TestClient(app)
        r = _login(client, "alice", "n" * 5000)
        assert r.status_code == 303 and "/login" in r.headers["location"]

    def test_profile_password_change_to_a_long_passphrase(self):
        _make_user()
        client = TestClient(app)
        _login(client, "alice", PASSWORD)
        r = client.post(
            "/profile/password",
            data={
                "csrf": _csrf(client),
                "current_password": PASSWORD,
                "new_password": LONG,
                "confirm_password": LONG,
            },
            follow_redirects=False,
        )
        assert r.status_code == 303 and "Password+changed" in r.headers["location"]
        assert verify_password(LONG, _get_user("alice").password_hash)

    def test_profile_password_change_over_the_cap_is_rejected_not_a_500(self):
        _make_user()
        client = TestClient(app)
        _login(client, "alice", PASSWORD)
        huge = "h" * (MAX_PASSWORD_CHARS + 1)
        r = client.post(
            "/profile/password",
            data={
                "csrf": _csrf(client),
                "current_password": PASSWORD,
                "new_password": huge,
                "confirm_password": huge,
            },
            follow_redirects=False,
        )
        assert r.status_code == 303 and "at+most" in r.headers["location"]
        assert verify_password(PASSWORD, _get_user("alice").password_hash)  # unchanged

    def test_admin_create_user_with_long_and_oversized_passwords(self):
        _make_user("root", role="admin")
        client = TestClient(app)
        _login(client, "root", PASSWORD)

        def create(name, pw):
            return client.post(
                "/admin/users/create",
                data={
                    "csrf": _csrf(client),
                    "username": name,
                    "email": f"{name}@example.com",
                    "display_name": "",
                    "role": "user",
                    "password": pw,
                },
                follow_redirects=False,
            )

        assert create("longuser", LONG).status_code == 303
        assert verify_password(LONG, _get_user("longuser").password_hash)
        r = create("hugeuser", "h" * (MAX_PASSWORD_CHARS + 1))
        assert r.status_code == 303 and "at+most" in r.headers["location"]
        assert _get_user("hugeuser") is None

    def test_setup_accepts_a_long_password_and_rejects_an_oversized_one(self, monkeypatch):
        import re

        from scry.config import get_settings

        monkeypatch.setenv("CTI_OPEN_ACCESS", "false")
        get_settings.cache_clear()
        with TestClient(app) as client:
            token = re.search(r'name="csrf" value="([^"]+)"', client.get("/setup").text).group(1)
            huge = "h" * (MAX_PASSWORD_CHARS + 1)
            r = client.post(
                "/setup",
                data={"csrf": token, "username": "root", "password": huge, "confirm_password": huge},
                follow_redirects=False,
            )
            assert r.status_code == 303 and "at+most" in r.headers["location"]
            assert _get_user("root") is None
            token = re.search(r'name="csrf" value="([^"]+)"', client.get("/setup").text).group(1)
            r = client.post(
                "/setup",
                data={"csrf": token, "username": "root", "password": LONG, "confirm_password": LONG},
                follow_redirects=False,
            )
            assert r.status_code == 303 and r.headers["location"] == "/"
            assert verify_password(LONG, _get_user("root").password_hash)
        get_settings.cache_clear()


class TestCli:
    def test_create_with_long_password(self):
        r = runner.invoke(
            cli_app, ["users", "create", "carol", "--email", "c@example.com", "--password", LONG]
        )
        assert r.exit_code == 0, r.output
        assert verify_password(LONG, _get_user("carol").password_hash)

    def test_create_over_the_cap_exits_cleanly(self):
        r = runner.invoke(
            cli_app,
            [
                "users",
                "create",
                "dave",
                "--email",
                "d@example.com",
                "--password",
                "d" * (MAX_PASSWORD_CHARS + 1),
            ],
        )
        assert r.exit_code == 2 and "at most" in r.output
        assert _get_user("dave") is None

    def test_reset_password_long_and_oversized(self):
        _make_user()
        r = runner.invoke(cli_app, ["users", "reset-password", "alice", "--password", LONG])
        assert r.exit_code == 0, r.output
        assert verify_password(LONG, _get_user("alice").password_hash)
        r = runner.invoke(
            cli_app, ["users", "reset-password", "alice", "--password", "r" * (MAX_PASSWORD_CHARS + 1)]
        )
        assert r.exit_code == 2 and "at most" in r.output
        assert verify_password(LONG, _get_user("alice").password_hash)  # unchanged

    def test_seed_with_long_and_oversized_passwords(self):
        r = runner.invoke(
            cli_app, ["users", "seed", "--username", "root", "--password", "s" * (MAX_PASSWORD_CHARS + 1)]
        )
        assert r.exit_code == 2 and _get_user("root") is None
        r = runner.invoke(cli_app, ["users", "seed", "--username", "root", "--password", LONG])
        assert r.exit_code == 0, r.output
        assert verify_password(LONG, _get_user("root").password_hash)
