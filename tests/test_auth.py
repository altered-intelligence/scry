"""Tests for v0.5.0 step 1: user accounts, bcrypt auth, DB sessions, login page,
UI + API gating, throttling, and the ``scry users`` CLI.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from scry.auth import sessions as sessions_mod
from scry.auth.passwords import hash_password, verify_password
from scry.auth.sessions import (
    SESSION_COOKIE,
    create_session,
    hash_token,
    lockout_remaining,
    revoke_all_sessions,
    revoke_session,
    validate_session,
)
from scry.cli import app as cli_app
from scry.config import get_settings
from scry.db import session_scope
from scry.main import app
from scry.models import AuditLog, SessionToken, User

PASSWORD = "S3cure!pass"
runner = CliRunner()


def make_user(
    username: str = "alice",
    password: str = PASSWORD,
    role: str = "user",
    status: str = "active",
    email: str | None = None,
    must_change_password: bool = False,
) -> int:
    with session_scope() as s:
        user = User(
            username=username,
            email=email or f"{username}@example.com",
            role=role,
            status=status,
            password_hash=hash_password(password),
            must_change_password=must_change_password,
        )
        s.add(user)
        s.flush()
        return user.id


def get_user(username: str) -> User:
    with session_scope() as s:
        return s.scalar(select(User).where(func.lower(User.username) == username.lower()))


def audit_actions() -> list[str]:
    with session_scope() as s:
        return [row.action for row in s.scalars(select(AuditLog))]


def login(client: TestClient, username: str = "alice", password: str = PASSWORD, **extra):
    return client.post(
        "/login", data={"username": username, "password": password, **extra}, follow_redirects=False
    )


# ------------------------- password hashing -------------------------


class TestPasswords:
    def test_hash_verify_roundtrip(self):
        hashed = hash_password(PASSWORD)
        assert hashed != PASSWORD
        assert hashed.startswith("$2")
        assert verify_password(PASSWORD, hashed)

    def test_wrong_password_rejected(self):
        assert not verify_password("nope", hash_password(PASSWORD))

    def test_malformed_hash_returns_false(self):
        assert not verify_password(PASSWORD, "not-a-bcrypt-hash")


# ------------------------- sessions -------------------------


class TestSessions:
    def test_raw_token_never_persisted(self):
        uid = make_user()
        with session_scope() as s:
            user = s.get(User, uid)
            raw = create_session(s, user, ip="127.0.0.1", user_agent="pytest")
            token = s.scalar(select(SessionToken).where(SessionToken.user_id == uid))
            assert token.token_hash == hash_token(raw)
            assert token.token_hash != raw
            assert raw not in token.token_hash
            assert token.ip == "127.0.0.1"

    def test_validate_and_revoke(self):
        uid = make_user()
        with session_scope() as s:
            user = s.get(User, uid)
            raw = create_session(s, user)
            assert validate_session(s, raw).id == uid
            assert validate_session(s, "bogus") is None
            assert validate_session(s, None) is None
            assert revoke_session(s, raw)
            assert validate_session(s, raw) is None
            raw2 = create_session(s, user)
            raw3 = create_session(s, user)
            assert revoke_all_sessions(s, uid) == 2
            assert validate_session(s, raw2) is None
            assert validate_session(s, raw3) is None

    def test_expired_session_rejected(self, monkeypatch):
        uid = make_user()
        start = datetime(2026, 1, 1, tzinfo=UTC)
        monkeypatch.setattr(sessions_mod, "utcnow", lambda: start)
        with session_scope() as s:
            user = s.get(User, uid)
            raw = create_session(s, user)
        later = start + timedelta(days=8)
        monkeypatch.setattr(sessions_mod, "utcnow", lambda: later)
        with session_scope() as s:
            assert validate_session(s, raw) is None
            # Expired token was cleaned up.
            assert s.scalar(select(SessionToken).where(SessionToken.user_id == uid)) is None

    def test_disabled_user_session_invalid(self):
        uid = make_user()
        with session_scope() as s:
            user = s.get(User, uid)
            raw = create_session(s, user)
            user.status = "disabled"
            s.flush()
            assert validate_session(s, raw) is None

    def test_sliding_expiry_extension(self, monkeypatch):
        uid = make_user()
        start = datetime(2026, 1, 1, tzinfo=UTC)
        monkeypatch.setattr(sessions_mod, "utcnow", lambda: start)
        with session_scope() as s:
            user = s.get(User, uid)
            raw = create_session(s, user)
        # 6.5 days later: < 24 h remain → expiry extended by another 7 days.
        day6 = start + timedelta(days=6, hours=12)
        monkeypatch.setattr(sessions_mod, "utcnow", lambda: day6)
        with session_scope() as s:
            assert validate_session(s, raw).id == uid
            token = s.scalar(select(SessionToken).where(SessionToken.user_id == uid))
            assert token.expires_at.replace(tzinfo=UTC) > day6 + timedelta(days=6)
            assert token.last_seen_at is not None


# ------------------------- login page + flow -------------------------


class TestLoginUI:
    def test_login_page_no_users_shows_note(self):
        with TestClient(app) as client:
            r = client.get("/login")
            assert r.status_code == 200
            assert "No accounts configured" in r.text
            assert 'name="username"' not in r.text

    def test_login_page_renders_form_when_users_exist(self):
        make_user()
        with TestClient(app) as client:
            r = client.get("/login")
            assert r.status_code == 200
            assert 'name="username"' in r.text
            assert 'name="password"' in r.text

    def test_full_login_cookie_dashboard_flow(self):
        make_user()
        with TestClient(app) as client:
            r = login(client)
            assert r.status_code == 303
            assert r.headers["location"] == "/"
            assert SESSION_COOKIE in client.cookies
            assert client.get("/").status_code == 200
            # Nav shows the signed-in username.
            assert "alice" in client.get("/").text

    def test_login_with_next_redirect(self):
        make_user()
        with TestClient(app) as client:
            r = login(client, next="/ui/search")
            assert r.headers["location"] == "/ui/search"

    def test_login_rejects_external_next(self):
        make_user()
        with TestClient(app) as client:
            r = login(client, next="https://evil.example.com/")
            assert r.headers["location"] == "/"

    def test_login_page_redirects_when_already_authed(self):
        make_user()
        with TestClient(app) as client:
            login(client)
            r = client.get("/login", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/"

    def test_bad_credentials_no_cookie(self):
        make_user()
        with TestClient(app) as client:
            r = client.post("/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False)
            assert r.status_code == 303
            assert "error=" in r.headers["location"]
            assert SESSION_COOKIE not in client.cookies

    def test_unknown_user_rejected(self):
        make_user()
        with TestClient(app) as client:
            r = client.post("/login", data={"username": "nobody", "password": "x"}, follow_redirects=False)
            assert "error=" in r.headers["location"]

    def test_logout_revokes_session(self):
        make_user()
        with TestClient(app) as client:
            login(client)
            assert client.get("/").status_code == 200
            r = client.post("/logout", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"
            assert client.get("/", follow_redirects=False).status_code == 303

    def test_disabled_user_rejected(self):
        make_user(status="disabled")
        with TestClient(app) as client:
            r = login(client)
            assert "disabled" in r.headers["location"]
            assert SESSION_COOKIE not in client.cookies

    def test_login_audit_records(self):
        make_user()
        with TestClient(app) as client:
            login(client, password="wrong")
            login(client)
        actions = audit_actions()
        assert "login.failure" in actions
        assert "login.success" in actions


# ------------------------- first-run setup page (v0.7.1) -------------------------


class TestFirstRunSetup:
    def _get_csrf(self, client: TestClient) -> str:
        import re

        r = client.get("/setup")
        assert r.status_code == 200
        m = re.search(r'name="csrf" value="([^"]+)"', r.text)
        assert m, "setup page must carry a CSRF token"
        return m.group(1)

    def test_setup_page_renders_with_zero_users(self):
        with TestClient(app) as client:
            r = client.get("/setup")
            assert r.status_code == 200
            assert "Create first administrator account" in r.text
            assert 'name="confirm_password"' in r.text
            # The zero-users login page points at /setup.
            r = client.get("/login")
            assert "/setup" in r.text

    def test_setup_creates_admin_and_signs_in(self):
        with TestClient(app) as client:
            csrf = self._get_csrf(client)
            r = client.post(
                "/setup",
                data={
                    "csrf": csrf,
                    "username": "root",
                    "password": "Sup3r!pass",
                    "confirm_password": "Sup3r!pass",
                    "email": "root@example.com",
                },
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            assert r.headers["location"] == "/"
            assert SESSION_COOKIE in client.cookies
            user = get_user("root")
            assert user.role == "admin"
            assert user.must_change_password is False
            assert verify_password("Sup3r!pass", user.password_hash)
            assert "user.setup" in audit_actions()

    def test_setup_default_email_when_omitted(self):
        with TestClient(app) as client:
            csrf = self._get_csrf(client)
            client.post(
                "/setup",
                data={
                    "csrf": csrf,
                    "username": "root",
                    "password": "Sup3r!pass",
                    "confirm_password": "Sup3r!pass",
                },
                follow_redirects=False,
            )
            assert get_user("root").email == "root@example.com"

    def test_setup_rejects_mismatched_passwords(self):
        with TestClient(app) as client:
            csrf = self._get_csrf(client)
            r = client.post(
                "/setup",
                data={
                    "csrf": csrf,
                    "username": "root",
                    "password": "Sup3r!pass",
                    "confirm_password": "Different!1",
                },
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "do+not+match" in r.headers["location"] or "not match" in r.headers["location"]
            assert get_user("root") is None

    def test_setup_rejects_bad_csrf(self):
        with TestClient(app) as client:
            r = client.post(
                "/setup",
                data={
                    "csrf": "forged",
                    "username": "root",
                    "password": "Sup3r!pass",
                    "confirm_password": "Sup3r!pass",
                },
                follow_redirects=False,
            )
            assert r.status_code == 403
            assert get_user("root") is None

    def test_setup_unreachable_once_users_exist(self):
        make_user()
        with TestClient(app) as client:
            assert client.get("/setup").status_code == 404
            r = client.post(
                "/setup",
                data={
                    "csrf": "whatever",
                    "username": "eve",
                    "password": "Sup3r!pass",
                    "confirm_password": "Sup3r!pass",
                },
                follow_redirects=False,
            )
            assert r.status_code == 404
            assert get_user("eve") is None


# ------------------------- throttling -------------------------


class TestThrottling:
    def test_lockout_after_five_failures(self, monkeypatch):
        make_user()
        start = datetime(2026, 1, 1, tzinfo=UTC)
        fake_now = {"now": start}
        monkeypatch.setattr(sessions_mod, "utcnow", lambda: fake_now["now"])
        with TestClient(app) as client:
            for _ in range(4):
                r = client.post(
                    "/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False
                )
                assert "locked" not in r.headers["location"]
            # 5th failure locks the account.
            r = client.post("/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False)
            assert "locked" in r.headers["location"].lower()
            # Correct password is still rejected while locked.
            r = login(client)
            assert "locked" in r.headers["location"].lower()
            assert SESSION_COOKIE not in client.cookies
            # After the lockout expires, a correct password works again.
            fake_now["now"] = start + timedelta(minutes=16)
            r = login(client)
            assert r.headers["location"] == "/"
            # Counter was reset on success.
            assert lockout_remaining(get_user("alice")) is None

    def test_failed_counter_increments(self):
        uid = make_user()
        with TestClient(app) as client:
            client.post("/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False)
            client.post("/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False)
        with session_scope() as s:
            assert s.get(User, uid).failed_login_count == 2

    def test_lockout_remaining_message_minutes(self, monkeypatch):
        make_user()
        start = datetime(2026, 1, 1, tzinfo=UTC)
        fake_now = {"now": start}
        monkeypatch.setattr(sessions_mod, "utcnow", lambda: fake_now["now"])
        with TestClient(app) as client:
            for _ in range(5):
                client.post("/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False)
        user = get_user("alice")
        assert lockout_remaining(user, now=start) is not None
        assert lockout_remaining(user, now=start + timedelta(minutes=16)) is None


# ------------------------- gating: legacy open + protected -------------------------


class TestGating:
    def test_legacy_open_when_no_users(self):
        with TestClient(app) as client:
            assert client.get("/").status_code == 200
            assert client.get("/ui/search").status_code == 200
            assert client.get("/articles").status_code == 200

    def test_ui_redirects_to_login_when_users_exist(self):
        make_user()
        with TestClient(app) as client:
            for path in ("/", "/ui/search", "/ui/articles", "/admin"):
                r = client.get(path, follow_redirects=False)
                assert r.status_code == 303
                assert r.headers["location"] == "/login"

    def test_login_and_static_exempt(self):
        make_user()
        with TestClient(app) as client:
            assert client.get("/login", follow_redirects=False).status_code == 200
            r = client.get("/static/logo.svg", follow_redirects=False)
            assert r.status_code == 200

    def test_api_rejects_when_users_exist_without_credentials(self):
        make_user()
        with TestClient(app) as client:
            r = client.get("/articles")
            assert r.status_code == 401

    def test_api_accepts_session_cookie_when_users_exist(self):
        make_user()
        with TestClient(app) as client:
            login(client)
            assert client.get("/articles").status_code == 200

    def test_api_accepts_master_key_when_users_exist(self, monkeypatch):
        make_user()
        monkeypatch.setenv("CTI_API_KEY", "master-key")
        get_settings.cache_clear()
        with TestClient(app) as client:
            assert client.get("/articles").status_code == 401
            assert client.get("/articles", headers={"X-API-Key": "master-key"}).status_code == 200
            assert client.get("/articles", headers={"Authorization": "Bearer master-key"}).status_code == 200

    def test_api_exemptions_open_when_users_exist(self):
        make_user()
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
            assert client.get("/api/ai/status").status_code == 200
            assert client.get("/api/ai/provider").status_code == 200

    def test_api_still_open_when_no_users_even_without_key(self):
        """Zero users: no key, no cookie — everything open (legacy behavior)."""
        with TestClient(app) as client:
            assert client.get("/articles").status_code == 200


# ------------------------- CLI -------------------------


class TestUsersCLI:
    def test_create_and_list(self):
        r = runner.invoke(
            cli_app, ["users", "create", "alice", "--email", "alice@example.com", "--password", PASSWORD]
        )
        assert r.exit_code == 0, r.output
        assert get_user("alice") is not None
        r = runner.invoke(cli_app, ["users", "list"])
        assert r.exit_code == 0
        assert "alice" in r.output
        assert "alice@example.com" in r.output

    def test_create_admin_flag_and_role(self):
        r = runner.invoke(
            cli_app,
            ["users", "create", "boss", "--email", "boss@example.com", "--password", PASSWORD, "--admin"],
        )
        assert r.exit_code == 0, r.output
        assert get_user("boss").role == "admin"

    def test_create_invalid_email_rejected(self):
        r = runner.invoke(
            cli_app, ["users", "create", "alice", "--email", "not-an-email", "--password", PASSWORD]
        )
        assert r.exit_code == 2

    def test_create_duplicate_rejected(self):
        make_user()
        r = runner.invoke(
            cli_app, ["users", "create", "ALICE", "--email", "x@example.com", "--password", PASSWORD]
        )
        assert r.exit_code == 1

    def test_promote_demote(self):
        make_user()
        assert runner.invoke(cli_app, ["users", "promote", "alice"]).exit_code == 0
        assert get_user("alice").role == "admin"
        assert runner.invoke(cli_app, ["users", "demote", "alice"]).exit_code == 0
        assert get_user("alice").role == "user"

    def test_reset_password(self):
        make_user()
        r = runner.invoke(cli_app, ["users", "reset-password", "alice", "--password", "N3w!pass"])
        assert r.exit_code == 0, r.output
        user = get_user("alice")
        assert verify_password("N3w!pass", user.password_hash)
        assert user.must_change_password is True

    def test_disable_enable(self):
        make_user()
        assert runner.invoke(cli_app, ["users", "disable", "alice"]).exit_code == 0
        assert get_user("alice").status == "disabled"
        assert runner.invoke(cli_app, ["users", "enable", "alice"]).exit_code == 0
        assert get_user("alice").status == "active"

    def test_seed_creates_single_admin_with_explicit_password(self):
        r = runner.invoke(cli_app, ["users", "seed", "--username", "root", "--password", "Seed3d!pass"])
        assert r.exit_code == 0, r.output
        user = get_user("root")
        assert user is not None
        assert user.role == "admin"
        assert user.must_change_password is True
        assert verify_password("Seed3d!pass", user.password_hash)

    def test_seed_generates_password_when_omitted(self):
        r = runner.invoke(cli_app, ["users", "seed", "--username", "root"])
        assert r.exit_code == 0, r.output
        # The generated one-time password is printed exactly once.
        marker = "One-time password"
        assert marker in r.output
        printed = r.output.split(marker, 1)[1].strip().splitlines()[1].strip()
        user = get_user("root")
        assert verify_password(printed, user.password_hash)
        assert user.must_change_password is True

    def test_seed_refuses_when_users_exist(self):
        make_user()
        r = runner.invoke(cli_app, ["users", "seed", "--username", "root", "--password", "Seed3d!pass"])
        assert r.exit_code == 1
        assert get_user("root") is None
        assert "already exist" in r.output

    def test_seed_requires_username(self):
        r = runner.invoke(cli_app, ["users", "seed"])
        assert r.exit_code == 2

    def test_seed_short_password_rejected(self):
        r = runner.invoke(cli_app, ["users", "seed", "--username", "root", "--password", "short"])
        assert r.exit_code == 2
        assert get_user("root") is None

    def test_user_mgmt_audited(self):
        make_user()
        runner.invoke(cli_app, ["users", "promote", "alice"])
        actions = audit_actions()
        assert "user.admin" in actions or "user.promote" in actions
