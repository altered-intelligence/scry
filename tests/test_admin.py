"""Tests for v0.5.0 step 2: the /admin control panel.

Covers the admin gate (login required, 403 for non-admins), user
management (create/edit/disable/enable/reset-password/delete), the
self-protection + last-admin guards, session revocation, the security
panel (failed logins / lockouts), stats, the DB-stored SMTP config with
env fallback + the test button (mocked smtplib), audit entries, and the
session-scoped CSRF token on every admin POST.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from scry.auth.passwords import hash_password, verify_password
from scry.auth.sessions import SESSION_COOKIE
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import AuditLog, SessionToken, SystemSetting, User

PASSWORD = "S3cure!pass"


def make_user(
    username: str = "alice",
    password: str = PASSWORD,
    role: str = "user",
    status: str = "active",
    email: str | None = None,
) -> int:
    with session_scope() as s:
        user = User(
            username=username,
            email=email or f"{username}@example.com",
            role=role,
            status=status,
            password_hash=hash_password(password),
        )
        s.add(user)
        s.flush()
        return user.id


def get_user(username: str) -> User:
    with session_scope() as s:
        return s.scalar(select(User).where(func.lower(User.username) == username.lower()))


def audit_entries() -> list[AuditLog]:
    with session_scope() as s:
        return list(s.scalars(select(AuditLog)))


def login(client: TestClient, username: str, password: str = PASSWORD):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def admin_client() -> TestClient:
    """A logged-in admin session (user 'root') with a valid CSRF token."""
    make_user("root", role="admin")
    client = TestClient(app)
    login(client, "root")
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    """Decode the flash message from a 303 Location header."""
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


# ------------------------- gate -------------------------


class TestAdminGate:
    def test_redirects_to_login_when_users_exist(self):
        make_user()
        with TestClient(app) as client:
            r = client.get("/admin", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"

    def test_forbidden_for_non_admin(self):
        make_user()
        with TestClient(app) as client:
            login(client, "alice")
            r = client.get("/admin")
            assert r.status_code == 403
            assert "Admins only" in r.text

    def test_ok_for_admin(self):
        make_user(role="admin")
        with TestClient(app) as client:
            login(client, "alice")
            r = client.get("/admin")
            assert r.status_code == 200
            for section in ("Users", "Create user", "Stats", "Security", "Active sessions",
                            "SMTP configuration", "Audit log"):
                assert section in r.text

    def test_zero_users_redirects_to_login_setup_note(self):
        with TestClient(app) as client:
            r = client.get("/admin", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"
            assert "No accounts configured" in client.get("/login").text

    def test_nav_link_shown_only_to_admins(self):
        make_user("root", role="admin")
        with TestClient(app) as client:
            login(client, "root")
            assert 'href="/admin"' in client.get("/").text
        make_user("bob")
        with TestClient(app) as client:
            login(client, "bob")
            assert 'href="/admin"' not in client.get("/").text

    def test_admin_posts_forbidden_for_non_admin(self):
        make_user()
        with TestClient(app) as client:
            login(client, "alice")
            r = client.post(
                "/admin/users/create",
                data={"csrf": "x", "username": "eve", "email": "eve@example.com"},
                follow_redirects=False,
            )
            assert r.status_code == 403


# ------------------------- user management -------------------------


def _create(client: TestClient, csrf: str, **overrides):
    data = {"csrf": csrf, "username": "bob", "email": "bob@example.com",
            "display_name": "", "role": "user", "password": "Init!pass123"}
    data.update(overrides)
    return client.post("/admin/users/create", data=data, follow_redirects=False)


class TestUserCreate:
    def test_create_with_initial_password(self):
        client = admin_client()
        r = _create(client, csrf_for(client))
        assert r.status_code == 303
        user = get_user("bob")
        assert user is not None
        assert user.role == "user"
        assert verify_password("Init!pass123", user.password_hash)
        assert user.must_change_password is False
        actions = [a.action for a in audit_entries()]
        assert "user.create" in actions

    def test_create_admin_role(self):
        client = admin_client()
        _create(client, csrf_for(client), role="admin")
        assert get_user("bob").role == "admin"

    def test_create_auto_generates_temp_password(self):
        client = admin_client()
        r = _create(client, csrf_for(client), password="")
        flash = flash_of(r)
        assert "temporary password" in flash
        temp = flash.split("temporary password (shown once): ")[1]
        user = get_user("bob")
        assert verify_password(temp, user.password_hash)
        assert user.must_change_password is True

    def test_create_invalid_email_rejected(self):
        client = admin_client()
        r = _create(client, csrf_for(client), email="not-an-email")
        assert "Invalid email" in flash_of(r)
        assert get_user("bob") is None

    def test_create_duplicate_username_rejected(self):
        make_user("BOB")
        client = admin_client()
        r = _create(client, csrf_for(client))
        assert "already exists" in flash_of(r)

    def test_create_invalid_role_rejected(self):
        client = admin_client()
        r = _create(client, csrf_for(client), role="superuser")
        assert "Role must" in flash_of(r)
        assert get_user("bob") is None


class TestUserEdit:
    def test_edit_display_name_email_role(self):
        make_user("bob")
        client = admin_client()
        uid = get_user("bob").id
        r = client.post(
            f"/admin/users/{uid}/edit",
            data={"csrf": csrf_for(client), "email": "new@example.com",
                  "display_name": "Bobby", "role": "admin"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        user = get_user("bob")
        assert user.email == "new@example.com"
        assert user.display_name == "Bobby"
        assert user.role == "admin"
        assert "user.update" in [a.action for a in audit_entries()]

    def test_edit_own_role_blocked(self):
        client = admin_client()
        uid = get_user("root").id
        client.post(
            f"/admin/users/{uid}/edit",
            data={"csrf": csrf_for(client), "email": "root@example.com",
                  "display_name": "", "role": "user"},
            follow_redirects=False,
        )
        assert get_user("root").role == "admin"

    def test_demote_last_admin_blocked(self):
        client = admin_client()
        uid = get_user("root").id
        r = client.post(
            f"/admin/users/{uid}/edit",
            data={"csrf": csrf_for(client), "email": "root@example.com",
                  "display_name": "", "role": "user"},
            follow_redirects=False,
        )
        assert "last admin" in flash_of(r)
        assert get_user("root").role == "admin"


class TestUserToggle:
    def test_disable_revokes_sessions_and_blocks_login(self):
        make_user("bob")
        with TestClient(app) as bob_client:
            login(bob_client, "bob")
        client = admin_client()
        uid = get_user("bob").id
        r = client.post(f"/admin/users/{uid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert "Disabled" in flash_of(r)
        assert get_user("bob").status == "disabled"
        with session_scope() as s:
            assert s.scalar(select(SessionToken).where(SessionToken.user_id == uid)) is None
        with TestClient(app) as bob_client:
            r = login(bob_client, "bob")
            assert "disabled" in r.headers["location"]
        assert "user.disable" in [a.action for a in audit_entries()]

    def test_enable_reactivates(self):
        make_user("bob", status="disabled")
        client = admin_client()
        uid = get_user("bob").id
        client.post(f"/admin/users/{uid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert get_user("bob").status == "active"
        assert "user.enable" in [a.action for a in audit_entries()]

    def test_disable_self_blocked(self):
        client = admin_client()
        uid = get_user("root").id
        client.post(f"/admin/users/{uid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert get_user("root").status == "active"


class TestResetPassword:
    def test_reset_shows_temp_password_once(self):
        make_user("bob")
        with TestClient(app) as bob_client:
            login(bob_client, "bob")
        client = admin_client()
        uid = get_user("bob").id
        r = client.post(
            f"/admin/users/{uid}/reset-password", data={"csrf": csrf_for(client)}, follow_redirects=False
        )
        flash = flash_of(r)
        assert "temporary password (shown once):" in flash
        temp = flash.split("temporary password (shown once): ")[1]
        user = get_user("bob")
        assert verify_password(temp, user.password_hash)
        assert user.must_change_password is True
        # Old sessions were revoked: the temp password itself logs in.
        with TestClient(app) as bob_client:
            r = login(bob_client, "bob", temp)
            assert r.headers["location"] == "/"
        assert "user.reset_password" in [a.action for a in audit_entries()]


class TestDeleteUser:
    def test_delete_removes_user_and_cascades_sessions(self):
        make_user("bob")
        with TestClient(app) as bob_client:
            login(bob_client, "bob")
        client = admin_client()
        uid = get_user("bob").id
        r = client.post(
            f"/admin/users/{uid}/delete",
            data={"csrf": csrf_for(client), "confirm": "bob"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert get_user("bob") is None
        with session_scope() as s:
            assert s.scalar(select(SessionToken).where(SessionToken.user_id == uid)) is None
        assert "user.delete" in [a.action for a in audit_entries()]

    def test_delete_self_blocked(self):
        client = admin_client()
        uid = get_user("root").id
        client.post(
            f"/admin/users/{uid}/delete",
            data={"csrf": csrf_for(client), "confirm": "root"},
            follow_redirects=False,
        )
        assert get_user("root") is not None

    def test_delete_last_admin_blocked(self):
        client = admin_client()
        uid = get_user("root").id
        r = client.post(
            f"/admin/users/{uid}/delete",
            data={"csrf": csrf_for(client), "confirm": "root"},
            follow_redirects=False,
        )
        assert "last admin" in flash_of(r)
        assert get_user("root") is not None

    def test_delete_requires_confirm(self):
        make_user("bob")
        client = admin_client()
        uid = get_user("bob").id
        r = client.post(
            f"/admin/users/{uid}/delete",
            data={"csrf": csrf_for(client), "confirm": "wrong"},
            follow_redirects=False,
        )
        assert "not confirmed" in flash_of(r)
        assert get_user("bob") is not None


# ------------------------- stats -------------------------


class TestAdminStats:
    def test_user_and_session_counts(self):
        make_user("bob")
        make_user("carol")
        with TestClient(app) as bob_client:
            login(bob_client, "bob")
        client = admin_client()
        r = client.get("/admin")
        assert r.status_code == 200
        assert '<div class="num">3</div><div class="lbl">users</div>' in r.text
        assert '<div class="num">2</div><div class="lbl">active sessions</div>' in r.text
        assert '<div class="num">2</div><div class="lbl">active last 7d</div>' in r.text

    def test_app_stats_reused(self):
        client = admin_client()
        r = client.get("/admin")
        for label in ("articles", "observables", "CVEs", "alerts"):
            assert label in r.text


# ------------------------- security panel -------------------------


class TestSecurityPanel:
    def test_failed_logins_listed(self):
        make_user("bob")
        with TestClient(app) as bob_client:
            bob_client.post("/login", data={"username": "bob", "password": "wrong"}, follow_redirects=False)
        client = admin_client()
        r = client.get("/admin")
        assert r.status_code == 200
        assert "Recent failed logins" in r.text
        assert "bob" in r.text

    def test_locked_accounts_listed(self):
        uid = make_user("bob")
        with session_scope() as s:
            s.get(User, uid).locked_until = datetime.now(UTC) + timedelta(minutes=10)
        client = admin_client()
        r = client.get("/admin")
        assert "Currently locked accounts" in r.text
        assert "bob" in r.text

    def test_no_lockouts_shows_empty_state(self):
        client = admin_client()
        r = client.get("/admin")
        assert "No locked accounts." in r.text


# ------------------------- sessions -------------------------


class TestSessionRevocation:
    def test_sessions_listed_and_revoked(self):
        make_user("bob")
        with TestClient(app) as bob_client:
            login(bob_client, "bob")
            bob_cookie = bob_client.cookies[SESSION_COOKIE]
        client = admin_client()
        r = client.get("/admin")
        assert "Active sessions" in r.text
        with session_scope() as s:
            token = s.scalar(select(SessionToken).join(User).where(User.username == "bob"))
            token_id = token.id
        r = client.post(f"/admin/sessions/{token_id}/revoke", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert r.status_code == 303
        with session_scope() as s:
            assert s.get(SessionToken, token_id) is None
        # Bob's cookie no longer works.
        with TestClient(app) as bob_client:
            bob_client.cookies.set(SESSION_COOKIE, bob_cookie)
            r = bob_client.get("/", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"
        assert "session.revoke" in [a.action for a in audit_entries()]

    def test_revoke_all_sessions_for_user(self):
        make_user("bob")
        with TestClient(app) as c1:
            login(c1, "bob")
        with TestClient(app) as c2:
            login(c2, "bob")
        client = admin_client()
        uid = get_user("bob").id
        r = client.post(
            f"/admin/users/{uid}/revoke-sessions", data={"csrf": csrf_for(client)}, follow_redirects=False
        )
        assert "Revoked 2 session" in flash_of(r)
        with session_scope() as s:
            assert s.scalar(select(SessionToken).where(SessionToken.user_id == uid)) is None


# ------------------------- SMTP config -------------------------


def _save_smtp(client: TestClient, csrf: str, **overrides):
    data = {"csrf": csrf, "host": "smtp.example.com", "port": "587", "user": "mailer",
            "password": "s3cret!", "starttls": "on", "from_address": "scry@example.com"}
    data.update(overrides)
    return client.post("/admin/smtp/save", data=data, follow_redirects=False)


class TestSMTPConfig:
    def test_save_persists_encrypted_and_overrides_env(self, monkeypatch):
        monkeypatch.setenv("CTI_SMTP_HOST", "env-host")
        from scry.config import get_settings

        get_settings.cache_clear()
        client = admin_client()
        r = _save_smtp(client, csrf_for(client))
        assert r.status_code == 303
        with session_scope() as s:
            rows = {row.key: row.value for row in s.scalars(select(SystemSetting))}
        assert rows["smtp.host"] == "smtp.example.com"
        assert rows["smtp.port"] == "587"
        assert rows["smtp.user"] == "mailer"
        assert rows["smtp.starttls"] == "true"
        assert rows["smtp.from_address"] == "scry@example.com"
        assert rows["smtp.password"] != "s3cret!"  # encrypted at rest
        # Effective config comes from the DB, not the env.
        from scry.mail import get_smtp_config, smtp_configured

        with session_scope() as s:
            assert smtp_configured(s)
            config = get_smtp_config(s)
        assert config.host == "smtp.example.com"
        assert config.password == "s3cret!"
        assert config.starttls is True
        assert "smtp.update" in [a.action for a in audit_entries()]

    def test_env_fallback_when_no_db_config(self, monkeypatch):
        monkeypatch.setenv("CTI_SMTP_HOST", "env-host")
        monkeypatch.setenv("CTI_SMTP_USER", "env-user")
        from scry.config import get_settings

        get_settings.cache_clear()
        with session_scope() as s:
            from scry.mail import get_smtp_config

            config = get_smtp_config(s)
        assert config.host == "env-host"
        assert config.user == "env-user"

    def test_unconfigured_when_no_host(self):
        with session_scope() as s:
            from scry.mail import smtp_configured

            assert not smtp_configured(s)

    def test_blank_host_clears_db_overrides(self):
        client = admin_client()
        _save_smtp(client, csrf_for(client))
        r = _save_smtp(client, csrf_for(client), host=" ", port="465", from_address="")
        assert "cleared" in flash_of(r)
        with session_scope() as s:
            assert s.scalar(select(SystemSetting).where(SystemSetting.key.like("smtp.%"))) is None
        assert "smtp.clear" in [a.action for a in audit_entries()]

    def test_invalid_port_rejected(self):
        client = admin_client()
        r = _save_smtp(client, csrf_for(client), port="abc")
        assert "Invalid port" in flash_of(r)
        with session_scope() as s:
            assert s.scalar(select(SystemSetting)) is None

    def test_blank_password_keeps_existing(self):
        client = admin_client()
        _save_smtp(client, csrf_for(client), password="first-pass")
        _save_smtp(client, csrf_for(client), password="")
        with session_scope() as s:
            rows = {row.key: row.value for row in s.scalars(select(SystemSetting))}
        from scry.crypto import decrypt

        assert decrypt(rows["smtp.password"]) == "first-pass"

    def test_test_button_success(self, monkeypatch):
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                sent["host"] = host

            def starttls(self):
                sent["starttls"] = True

            def login(self, user, password):
                sent["login"] = (user, password)

            def send_message(self, msg):
                sent["to"] = msg["To"]

            def quit(self):
                pass

        monkeypatch.setattr("scry.mail.smtplib.SMTP", FakeSMTP)
        client = admin_client()
        _save_smtp(client, csrf_for(client))
        r = client.post(
            "/admin/smtp/test",
            data={"csrf": csrf_for(client), "test_to": "ops@example.com"},
            follow_redirects=False,
        )
        assert "SMTP test OK" in flash_of(r)
        assert sent["host"] == "smtp.example.com"
        assert sent["starttls"] is True
        assert sent["login"] == ("mailer", "s3cret!")
        assert sent["to"] == "ops@example.com"
        tests = [a for a in audit_entries() if a.action == "smtp.test"]
        assert tests and tests[0].detail["ok"] is True

    def test_test_button_failure(self, monkeypatch):
        class Boom:
            def __init__(self, *a, **k):
                raise OSError("connection refused")

        monkeypatch.setattr("scry.mail.smtplib.SMTP", Boom)
        client = admin_client()
        _save_smtp(client, csrf_for(client))
        r = client.post(
            "/admin/smtp/test", data={"csrf": csrf_for(client), "test_to": ""}, follow_redirects=False
        )
        assert "SMTP test failed" in flash_of(r)

    def test_test_button_unconfigured(self):
        client = admin_client()
        r = client.post(
            "/admin/smtp/test", data={"csrf": csrf_for(client), "test_to": ""}, follow_redirects=False
        )
        assert "SMTP test failed" in flash_of(r)


class TestMailer:
    def test_send_mail_unconfigured_returns_false(self):
        with session_scope() as s:
            from scry.mail import send_mail

            assert send_mail(s, "subject", "body", "to@example.com") is False

    def test_send_mail_uses_db_config(self, monkeypatch):
        sent = {}

        class FakeSMTPSSL:
            def __init__(self, host, port, timeout=None):
                sent["host"] = host

            def login(self, user, password):
                sent["login"] = (user, password)

            def send_message(self, msg):
                sent["subject"] = msg["Subject"]
                sent["to"] = msg["To"]
                sent["from"] = msg["From"]
                sent["body"] = msg.get_content()

            def quit(self):
                pass

        monkeypatch.setattr("scry.mail.smtplib.SMTP_SSL", FakeSMTPSSL)
        with session_scope() as s:
            from scry.mail import save_smtp_config, send_mail

            save_smtp_config(
                s, host="smtp.example.com", port=465, user="mailer", password="pw",
                starttls=False, from_address="scry@example.com",
            )
            assert send_mail(s, "Hello", "Body text", "to@example.com") is True
        assert sent["host"] == "smtp.example.com"
        assert sent["login"] == ("mailer", "pw")
        assert sent["subject"] == "Hello"
        assert sent["to"] == "to@example.com"
        assert sent["from"] == "scry@example.com"
        assert "Body text" in sent["body"]

    def test_test_smtp_probe_connects_only(self, monkeypatch):
        calls = {"send": 0}

        class FakeSMTP:
            def __init__(self, *a, **k):
                pass

            def login(self, *a):
                calls["login"] = True

            def send_message(self, msg):
                calls["send"] += 1

            def quit(self):
                pass

        monkeypatch.setattr("scry.mail.smtplib.SMTP", FakeSMTP)
        with session_scope() as s:
            from scry.mail import save_smtp_config, test_smtp

            save_smtp_config(
                s, host="smtp.example.com", port=587, user="mailer", password="pw",
                starttls=False, from_address="scry@example.com",
            )
            ok, error = test_smtp(s)
        assert ok is True
        assert error is None
        assert calls["login"] is True
        assert calls["send"] == 0


# ------------------------- CSRF -------------------------


class TestCSRF:
    def test_missing_token_rejected(self):
        client = admin_client()
        r = _create(client, "")  # blank CSRF
        assert "Bad CSRF token" in flash_of(r)
        assert get_user("bob") is None

    def test_wrong_token_rejected(self):
        client = admin_client()
        r = _create(client, "forged-token")
        assert "Bad CSRF token" in flash_of(r)
        assert get_user("bob") is None

    def test_token_bound_to_session(self):
        """A token from another session does not validate."""
        make_user("root", role="admin")
        make_user("other", role="admin")
        with TestClient(app) as c1:
            login(c1, "root")
            foreign = csrf_for(c1)
        with TestClient(app) as c2:
            login(c2, "other")
            r = _create(c2, foreign)
            assert "Bad CSRF token" in flash_of(r)
            assert get_user("bob") is None


# ------------------------- audit -------------------------


class TestAdminAudit:
    def test_actions_recorded_with_actor(self):
        client = admin_client()
        _create(client, csrf_for(client))
        uid = get_user("bob").id
        client.post(f"/admin/users/{uid}/toggle", data={"csrf": csrf_for(client)}, follow_redirects=False)
        entries = {a.action: a for a in audit_entries()}
        assert entries["user.create"].actor == "root"
        assert entries["user.create"].target_id == uid
        assert entries["user.disable"].actor == "root"

    def test_audit_log_section_shows_entries(self):
        client = admin_client()
        r = client.get("/admin")
        assert "Audit log" in r.text
        assert "login.success" in r.text


def test_csrf_token_unique_per_session():
    """Tokens from two sessions differ (they are bound to the session hash)."""
    make_user("root", role="admin")
    make_user("other", role="admin")
    with TestClient(app) as c1:
        login(c1, "root")
        t1 = csrf_for(c1)
    with TestClient(app) as c2:
        login(c2, "other")
        t2 = csrf_for(c2)
    assert t1 and t2 and t1 != t2
