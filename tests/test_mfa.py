"""Tests for v0.5.0 step 4: TOTP MFA.

Follows the test_profile.py pattern: real HTTP calls through TestClient
against an isolated SQLite DB. pyotp is real — tests compute valid codes from
the stored secret via ``pyotp.TOTP(secret).now()``; time travel for the
expiring pending-login marker uses freezegun.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time
from sqlalchemy import func, select

from scry.auth import totp as totp_helpers
from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE, hash_token
from scry.crypto import decrypt
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import AuditLog, RecoveryCode, SessionToken, User

PASSWORD = "S3cure!pass"


@pytest.fixture(autouse=True)
def _clear_mfa_attempts():
    """The in-memory challenge-attempt counter is keyed by user id; DBs are
    per-test so ids repeat — reset between tests."""
    totp_helpers._mfa_attempts.clear()
    yield
    totp_helpers._mfa_attempts.clear()


def make_user(
    username: str = "alice",
    password: str = PASSWORD,
    role: str = "user",
) -> int:
    with session_scope() as s:
        user = User(
            username=username,
            email=f"{username}@example.com",
            role=role,
            password_hash=hash_password(password),
        )
        s.add(user)
        s.flush()
        return user.id


def get_user(username: str = "alice") -> User:
    with session_scope() as s:
        return s.scalar(select(User).where(func.lower(User.username) == username.lower()))


def audit_entries() -> list[AuditLog]:
    with session_scope() as s:
        return list(s.scalars(select(AuditLog)))


def login(client: TestClient, username: str = "alice", password: str = PASSWORD):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def profile_client(username: str = "alice") -> TestClient:
    client = TestClient(app)
    login(client, username)
    return client


def mfa_profile_client(username: str = "alice") -> TestClient:
    """A logged-in session for a user WITH MFA enabled (password + TOTP)."""
    client = TestClient(app)
    mfa_password_step(client, username)
    r = submit_challenge(client, totp_code(username))
    assert r.status_code == 303 and SESSION_COOKIE in client.cookies
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


def secret_of(username: str = "alice") -> str:
    return decrypt(get_user(username).totp_secret_encrypted)


def totp_code(username: str = "alice") -> str:
    return pyotp.TOTP(secret_of(username)).now()


def recovery_code_rows(username: str = "alice") -> list[RecoveryCode]:
    uid = get_user(username).id
    with session_scope() as s:
        return list(s.scalars(select(RecoveryCode).where(RecoveryCode.user_id == uid)))


def start_setup(client: TestClient, password: str = PASSWORD):
    return client.post(
        "/profile/mfa/setup",
        data={"csrf": csrf_for(client), "password": password},
        follow_redirects=False,
    )


def verify_setup(client: TestClient, code: str):
    return client.post(
        "/profile/mfa/verify",
        data={"csrf": csrf_for(client), "code": code},
        follow_redirects=False,
    )


def enable_mfa(username: str = "alice", password: str = PASSWORD) -> tuple[str, list[str]]:
    """Full happy-path setup; returns (totp_secret, recovery_codes)."""
    if get_user(username) is None:
        make_user(username, password)
    client = profile_client(username)
    r = start_setup(client, password)
    assert r.status_code == 303
    r = verify_setup(client, totp_code(username))
    assert r.status_code == 200
    codes = parse_recovery_codes(r.text)
    assert len(codes) == totp_helpers.RECOVERY_CODE_COUNT
    return secret_of(username), codes


def parse_recovery_codes(page_text: str) -> list[str]:
    m = re.search(r"<textarea[^>]*>(.*?)</textarea>", page_text, re.S)
    assert m, "recovery-codes textarea not found"
    return [line.strip() for line in m.group(1).strip().splitlines() if line.strip()]


def mfa_password_step(client: TestClient, username: str = "alice", next: str | None = None):
    data = {"username": username, "password": PASSWORD}
    if next:
        data["next"] = next
    r = client.post("/login", data=data, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login/mfa")
    assert totp_helpers.MFA_PENDING_COOKIE in client.cookies
    return r


def submit_challenge(client: TestClient, code: str, next: str | None = None):
    data = {"code": code}
    if next:
        data["next"] = next
    return client.post("/login/mfa", data=data, follow_redirects=False)


# ------------------------- setup flow -------------------------


class TestMfaSetup:
    def test_profile_page_shows_mfa_section(self):
        make_user()
        client = profile_client()
        page = client.get("/profile").text
        assert "Two-factor authentication" in page
        assert "disabled" in page
        assert 'name="password"' in page

    def test_setup_requires_password_and_csrf(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/mfa/setup",
            data={"csrf": csrf_for(client), "password": "wrong-pass"},
            follow_redirects=False,
        )
        assert "Password is incorrect" in flash_of(r)
        r = client.post(
            "/profile/mfa/setup",
            data={"csrf": "forged", "password": PASSWORD},
            follow_redirects=False,
        )
        assert "Bad CSRF token" in flash_of(r)
        user = get_user()
        assert user.totp_secret_encrypted is None and user.totp_pending is False

    def test_setup_shows_qr_and_manual_code_pending(self):
        make_user()
        client = profile_client()
        r = start_setup(client)
        assert r.status_code == 303
        user = get_user()
        assert user.totp_pending is True
        assert user.totp_enabled is False
        secret = decrypt(user.totp_secret_encrypted)
        assert secret
        page = client.get("/profile").text
        assert "data:image/png;base64," in page  # QR rendered inline
        assert secret in page  # manual entry key
        assert "setup in progress" in page
        assert 'action="/profile/mfa/verify"' in page
        assert 'action="/profile/mfa/cancel"' in page
        assert "mfa.setup" in [a.action for a in audit_entries()]

    def test_verify_enables_and_shows_10_codes_once(self):
        make_user()
        client = profile_client()
        start_setup(client)
        r = verify_setup(client, totp_code())
        assert r.status_code == 200
        user = get_user()
        assert user.totp_enabled is True
        assert user.totp_pending is False
        codes = parse_recovery_codes(r.text)
        assert len(codes) == 10
        assert len(set(codes)) == 10
        rows = recovery_code_rows()
        assert len(rows) == 10
        for code, row in zip(codes, rows, strict=True):
            assert row.code_hash == totp_helpers.hash_recovery_code(code)
            assert row.code_hash != code  # hash only, at rest
            assert row.used_at is None
        # Shown once: a later page load no longer contains them.
        page = client.get("/profile").text
        assert "enabled" in page
        assert "unused recovery code" in page
        for code in codes:
            assert code not in page
        actions = [a.action for a in audit_entries()]
        assert "mfa.enable" in actions

    def test_wrong_code_rejected_but_retry_allowed(self):
        make_user()
        client = profile_client()
        start_setup(client)
        wrong = "000000" if totp_code() != "000000" else "000001"
        r = verify_setup(client, wrong)
        assert r.status_code == 303
        assert "Incorrect code" in flash_of(r)
        user = get_user()
        assert user.totp_enabled is False
        assert user.totp_pending is True  # still pending → can retry
        r = verify_setup(client, totp_code())
        assert r.status_code == 200
        assert get_user().totp_enabled is True

    def test_cancel_setup_clears_secret(self):
        make_user()
        client = profile_client()
        start_setup(client)
        r = client.post(
            "/profile/mfa/cancel",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        user = get_user()
        assert user.totp_pending is False
        assert user.totp_secret_encrypted is None
        assert "mfa.setup_cancel" in [a.action for a in audit_entries()]
        page = client.get("/profile").text
        assert 'action="/profile/mfa/setup"' in page  # back to the start state


# ------------------------- login challenge -------------------------


class TestMfaLogin:
    def test_password_step_sets_pending_cookie_no_session(self):
        enable_mfa()
        with session_scope() as s:
            before = len(s.scalars(select(SessionToken)).all())
        client = TestClient(app)
        mfa_password_step(client)
        assert SESSION_COOKIE not in client.cookies
        with session_scope() as s:
            assert len(s.scalars(select(SessionToken)).all()) == before  # no new session

    def test_valid_totp_completes_login(self):
        enable_mfa()
        client = TestClient(app)
        mfa_password_step(client, next="/ui/articles")
        page = client.get("/login/mfa")
        assert page.status_code == 200
        assert "Two-factor authentication" in page.text
        r = submit_challenge(client, totp_code(), next="/ui/articles")
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/articles"
        assert SESSION_COOKIE in client.cookies
        assert totp_helpers.MFA_PENDING_COOKIE not in client.cookies
        assert client.get("/ui/articles").status_code == 200
        entry = [a for a in audit_entries() if a.action == "login.success"][-1]
        assert entry.detail["via"] == "totp"

    def test_wrong_totp_rejected(self):
        enable_mfa()
        client = TestClient(app)
        mfa_password_step(client)
        wrong = "000000" if totp_code() != "000000" else "000001"
        r = submit_challenge(client, wrong)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login/mfa")
        assert "Invalid authentication code" in parse_qs(urlparse(r.headers["location"]).query)["error"][0]
        assert SESSION_COOKIE not in client.cookies

    def test_five_failures_invalidate_pending(self):
        enable_mfa()
        client = TestClient(app)
        mfa_password_step(client)
        wrong = "000000" if totp_code() != "000000" else "000001"
        for _ in range(4):
            r = submit_challenge(client, wrong)
            assert r.headers["location"].startswith("/login/mfa")
        # The 5th failure sends the user back to the password step.
        r = submit_challenge(client, wrong)
        assert r.headers["location"].startswith("/login")
        assert "Too many failed codes" in parse_qs(urlparse(r.headers["location"]).query)["error"][0]
        assert totp_helpers.MFA_PENDING_COOKIE not in client.cookies
        # The marker is gone: even the right code now bounces to /login.
        r = submit_challenge(client, totp_code())
        assert r.headers["location"].startswith("/login")
        assert SESSION_COOKIE not in client.cookies

    def test_expired_pending_marker_rejected(self):
        enable_mfa()
        client = TestClient(app)
        with freeze_time(datetime(2030, 1, 1, 12, 0, tzinfo=UTC)):
            mfa_password_step(client)
        with freeze_time(datetime(2030, 1, 1, 12, 6, tzinfo=UTC)):
            r = client.get("/login/mfa", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"].startswith("/login")
            r = submit_challenge(client, totp_code())
            assert r.status_code == 303
            assert r.headers["location"].startswith("/login")
            assert SESSION_COOKIE not in client.cookies

    def test_challenge_without_marker_bounces_to_login(self):
        make_user()  # MFA not even enabled
        client = TestClient(app)
        r = submit_challenge(client, "123456")
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login")

    def test_mfa_user_without_pending_cookie_gets_no_session(self):
        """A stolen/guessed TOTP code is useless without the pending marker."""
        enable_mfa()
        client = TestClient(app)
        r = submit_challenge(client, totp_code())
        assert r.status_code == 303
        assert r.headers["location"].startswith("/login")
        assert SESSION_COOKIE not in client.cookies

    def test_users_without_mfa_unaffected(self):
        make_user()
        client = TestClient(app)
        r = login(client)
        assert r.status_code == 303
        assert r.headers["location"] == "/"
        assert totp_helpers.MFA_PENDING_COOKIE not in client.cookies
        assert client.get("/").status_code == 200


# ------------------------- recovery codes -------------------------


class TestRecoveryCodes:
    def test_recovery_code_login_works_once(self):
        _, codes = enable_mfa()
        client = TestClient(app)
        mfa_password_step(client)
        r = submit_challenge(client, codes[0])
        assert r.status_code == 303
        assert SESSION_COOKIE in client.cookies
        row = [rc for rc in recovery_code_rows() if rc.used_at is not None]
        assert len(row) == 1
        assert row[0].code_hash == totp_helpers.hash_recovery_code(codes[0])
        actions = [a.action for a in audit_entries()]
        assert "mfa.recovery_code_use" in actions

    def test_recovery_code_second_use_fails(self):
        _, codes = enable_mfa()
        for i in range(2):
            client = TestClient(app)
            mfa_password_step(client)
            r = submit_challenge(client, codes[0])
            if i == 0:
                assert r.status_code == 303
                assert SESSION_COOKIE in client.cookies
            else:
                assert r.status_code == 303
                assert r.headers["location"].startswith("/login/mfa")
                assert SESSION_COOKIE not in client.cookies
        assert len([rc for rc in recovery_code_rows() if rc.used_at is not None]) == 1

    def test_wrong_recovery_code_rejected(self):
        enable_mfa()
        client = TestClient(app)
        mfa_password_step(client)
        r = submit_challenge(client, "not-a-real-code-zzz")
        assert r.headers["location"].startswith("/login/mfa")


# ------------------------- disable -------------------------


class TestMfaDisable:
    def test_wrong_password_rejected(self):
        enable_mfa()
        client = mfa_profile_client()
        r = client.post(
            "/profile/mfa/disable",
            data={"csrf": csrf_for(client), "password": "wrong-pass"},
            follow_redirects=False,
        )
        assert "Password is incorrect" in flash_of(r)
        assert get_user().totp_enabled is True

    def test_disable_clears_everything_and_revokes_other_sessions(self):
        enable_mfa()
        client_a = mfa_profile_client()
        client_b = TestClient(app)
        mfa_password_step(client_b)
        submit_challenge(client_b, totp_code())
        assert client_b.get("/").status_code == 200

        r = client_a.post(
            "/profile/mfa/disable",
            data={"csrf": csrf_for(client_a), "password": PASSWORD},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "2 other session" in flash_of(r)
        user = get_user()
        assert user.totp_enabled is False
        assert user.totp_pending is False
        assert user.totp_secret_encrypted is None
        assert recovery_code_rows() == []
        # Other sessions revoked; the current one survives.
        assert client_b.get("/", follow_redirects=False).status_code == 303
        assert client_a.get("/").status_code == 200
        with session_scope() as s:
            keep = hash_token(client_a.cookies[SESSION_COOKIE])
            tokens = s.scalars(select(SessionToken)).all()
            assert len(tokens) == 1 and tokens[0].token_hash == keep
        assert "mfa.disable" in [a.action for a in audit_entries()]

    def test_after_disable_login_skips_challenge(self):
        enable_mfa()
        client = mfa_profile_client()
        client.post(
            "/profile/mfa/disable",
            data={"csrf": csrf_for(client), "password": PASSWORD},
            follow_redirects=False,
        )
        fresh = TestClient(app)
        r = login(fresh)
        assert r.status_code == 303
        assert r.headers["location"] == "/"
        assert SESSION_COOKIE in fresh.cookies


# ------------------------- admin reset -------------------------


class TestAdminResetMfa:
    def _admin_client(self) -> TestClient:
        make_user("root", role="admin")
        client = TestClient(app)
        login(client, "root")
        return client

    def test_reset_requires_username_confirm(self):
        enable_mfa("alice")
        admin = self._admin_client()
        uid = get_user("alice").id
        r = admin.post(
            f"/admin/users/{uid}/reset-mfa",
            data={"csrf": csrf_for(admin), "confirm": "not-alice"},
            follow_redirects=False,
        )
        assert "Reset not confirmed" in flash_of(r)
        assert get_user("alice").totp_enabled is True

    def test_reset_disables_mfa_revokes_sessions_and_audits(self):
        enable_mfa("alice")
        alice = mfa_profile_client("alice")
        admin = self._admin_client()
        uid = get_user("alice").id
        r = admin.post(
            f"/admin/users/{uid}/reset-mfa",
            data={"csrf": csrf_for(admin), "confirm": "alice"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        user = get_user("alice")
        assert user.totp_enabled is False
        assert user.totp_secret_encrypted is None
        assert recovery_code_rows("alice") == []
        # All of alice's sessions revoked (incl. the admin-panel target's own).
        assert alice.get("/", follow_redirects=False).status_code == 303
        with session_scope() as s:
            assert s.scalars(select(SessionToken)).all() != []  # root's session stays
        entries = [a for a in audit_entries() if a.action == "mfa.admin_reset"]
        assert entries and entries[0].actor == "root"
        assert entries[0].detail["revoked_sessions"] == 2  # setup session + alice's session

    def test_reset_noop_when_mfa_not_enabled(self):
        make_user("alice")
        admin = self._admin_client()
        uid = get_user("alice").id
        r = admin.post(
            f"/admin/users/{uid}/reset-mfa",
            data={"csrf": csrf_for(admin), "confirm": "alice"},
            follow_redirects=False,
        )
        assert "does not have MFA enabled" in flash_of(r)

    def test_reset_requires_csrf_and_admin(self):
        enable_mfa("alice")
        admin = self._admin_client()
        uid = get_user("alice").id
        r = admin.post(
            f"/admin/users/{uid}/reset-mfa",
            data={"csrf": "forged", "confirm": "alice"},
            follow_redirects=False,
        )
        assert "Bad CSRF token" in flash_of(r)
        assert get_user("alice").totp_enabled is True

        alice = mfa_profile_client("alice")
        r = alice.post(
            f"/admin/users/{uid}/reset-mfa",
            data={"csrf": csrf_for(alice), "confirm": "alice"},
            follow_redirects=False,
        )
        assert r.status_code == 403
        assert get_user("alice").totp_enabled is True
