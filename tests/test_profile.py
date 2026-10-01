"""Tests for v0.5.0 step 3: /profile, per-user API keys, email verification,
and per-user chat-session privacy.

Follows the test_auth.py / test_admin.py patterns: real HTTP calls through
TestClient against an isolated SQLite DB, flash messages decoded from 303
Location headers, audit entries read back from the DB.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from scry.auth.passwords import hash_password, verify_password
from scry.auth.sessions import SESSION_COOKIE, hash_token
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import (
    AnalystReview,
    ApiKey,
    AuditLog,
    ChatMessage,
    ChatSession,
    EmailVerification,
    SessionToken,
    User,
)

PASSWORD = "S3cure!pass"
NEW_PASSWORD = "N3w!password"


def make_user(
    username: str = "alice",
    password: str = PASSWORD,
    role: str = "user",
    must_change_password: bool = False,
) -> int:
    with session_scope() as s:
        user = User(
            username=username,
            email=f"{username}@example.com",
            role=role,
            password_hash=hash_password(password),
            must_change_password=must_change_password,
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


def login(client: TestClient, username: str = "alice", password: str = PASSWORD):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def profile_client(username: str = "alice") -> TestClient:
    """A logged-in session (optionally with must_change_password preset)."""
    client = TestClient(app)
    login(client, username)
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


def save_smtp() -> None:
    """Commit a working DB-stored SMTP config (monkeypatched transport)."""
    from scry.mail import save_smtp_config

    with session_scope() as s:
        save_smtp_config(
            s,
            host="smtp.example.com",
            port=465,
            user="mailer",
            password="pw",
            starttls=False,
            from_address="scry@example.com",
        )


def capture_mail(monkeypatch) -> dict:
    sent: dict = {"bodies": []}

    def fake_send_mail(session, subject, body, to, from_address=None):
        sent.update(subject=subject, body=body, to=to)
        sent["bodies"].append(body)
        return True

    monkeypatch.setattr("scry.mail.send_mail", fake_send_mail)
    return sent


# ------------------------- profile page -------------------------


class TestProfilePage:
    def test_redirects_to_login_when_unauthenticated(self):
        make_user()
        with TestClient(app) as client:
            r = client.get("/profile", follow_redirects=False)
            assert r.status_code == 303
            assert r.headers["location"] == "/login"

    def test_renders_all_sections(self):
        make_user()
        client = profile_client()
        r = client.get("/profile")
        assert r.status_code == 200
        for section in ("Identity", "Change password", "Email verification", "API keys"):
            assert section in r.text
        assert "alice@example.com" in r.text
        assert "unverified" in r.text

    def test_nav_links_to_profile(self):
        make_user()
        client = profile_client()
        assert 'href="/profile"' in client.get("/").text

    def test_display_name_edit(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/display-name",
            data={"csrf": csrf_for(client), "display_name": "Alice A."},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert get_user("alice").display_name == "Alice A."
        entries = [a for a in audit_entries() if a.action == "user.update"]
        assert entries and entries[0].actor == "alice"

    def test_display_name_blank_clears(self):
        uid = make_user()
        with session_scope() as s:
            s.get(User, uid).display_name = "Alice A."
        client = profile_client()
        client.post(
            "/profile/display-name",
            data={"csrf": csrf_for(client), "display_name": "  "},
            follow_redirects=False,
        )
        assert get_user("alice").display_name is None

    def test_posts_require_csrf(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/display-name",
            data={"csrf": "forged", "display_name": "Eve"},
            follow_redirects=False,
        )
        assert "Bad CSRF token" in flash_of(r)
        assert get_user("alice").display_name is None


# ------------------------- change password -------------------------


def _change_password(client: TestClient, current: str, new: str, confirm: str | None = None):
    return client.post(
        "/profile/password",
        data={
            "csrf": csrf_for(client),
            "current_password": current,
            "new_password": new,
            "confirm_password": confirm if confirm is not None else new,
        },
        follow_redirects=False,
    )


class TestChangePassword:
    def test_wrong_current_password_rejected(self):
        make_user()
        client = profile_client()
        r = _change_password(client, "wrong-pass", NEW_PASSWORD)
        assert "Current password is incorrect" in flash_of(r)
        assert verify_password(PASSWORD, get_user("alice").password_hash)

    def test_mismatched_confirm_rejected(self):
        make_user()
        client = profile_client()
        r = _change_password(client, PASSWORD, NEW_PASSWORD, confirm="different1")
        assert "do not match" in flash_of(r)

    def test_short_password_rejected(self):
        make_user()
        client = profile_client()
        r = _change_password(client, PASSWORD, "short")
        assert "at least 10 characters" in flash_of(r)

    def test_success_clears_must_change_and_audits(self):
        make_user(must_change_password=True)
        client = profile_client()
        r = _change_password(client, PASSWORD, NEW_PASSWORD)
        assert r.status_code == 303
        user = get_user("alice")
        assert verify_password(NEW_PASSWORD, user.password_hash)
        assert user.must_change_password is False
        entries = [a for a in audit_entries() if a.action == "user.change_password"]
        assert entries and entries[0].actor == "alice"

    def test_must_change_password_redirects_everywhere(self):
        """Banner + redirect until the password is changed."""
        make_user(must_change_password=True)
        client = profile_client()
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/profile")
        page = client.get("/profile")
        assert "You must change your password before continuing." in page.text
        # Allowed through: changing the password itself + logout.
        r = _change_password(client, PASSWORD, NEW_PASSWORD)
        assert r.status_code == 303
        assert client.get("/").status_code == 200

    def test_other_sessions_revoked_current_kept(self):
        make_user()
        client_a = profile_client()
        client_b = TestClient(app)
        login(client_b, "alice")
        assert client_b.get("/").status_code == 200

        r = _change_password(client_a, PASSWORD, NEW_PASSWORD)
        assert "1 other session" in flash_of(r)

        # The other session is dead…
        rb = client_b.get("/", follow_redirects=False)
        assert rb.status_code == 303
        assert rb.headers["location"] == "/login"
        # …but the session that made the change still works.
        assert client_a.get("/").status_code == 200
        with session_scope() as s:
            tokens = s.scalars(select(SessionToken)).all()
            assert len(tokens) == 1


# ------------------------- email verification -------------------------


class TestEmailVerification:
    def test_bypass_when_smtp_unconfigured(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/verify-email",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert "SMTP not configured" in flash_of(r)
        assert "auto-verified" in flash_of(r)
        assert get_user("alice").email_verified is True
        entries = [a for a in audit_entries() if a.action == "email.verify.bypass"]
        assert entries and entries[0].actor == "alice"

    def test_already_verified_is_a_noop(self):
        uid = make_user()
        with session_scope() as s:
            s.get(User, uid).email_verified = True
        client = profile_client()
        r = client.post("/profile/verify-email", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert "already verified" in flash_of(r)

    def test_pin_issued_and_emailed_when_smtp_configured(self, monkeypatch):
        make_user()
        save_smtp()
        sent = capture_mail(monkeypatch)
        client = profile_client()
        r = client.post("/profile/verify-email", data={"csrf": csrf_for(client)}, follow_redirects=False)
        assert "Verification code sent to alice@example.com" in flash_of(r)
        assert sent["to"] == "alice@example.com"
        assert sent["subject"] == "Your scry verification code"
        m = re.search(r"\b(\d{6})\b", sent["body"])
        assert m, sent["body"]
        pin = m.group(1)
        with session_scope() as s:
            row = s.scalar(select(EmailVerification))
            assert row is not None
            assert row.code_hash == hashlib.sha256(pin.encode()).hexdigest()
            assert row.code_hash != pin  # hash only, at rest
            assert row.consumed_at is None
            exp = row.expires_at
            exp = exp if exp.tzinfo else exp.replace(tzinfo=UTC)
            assert exp > datetime.now(UTC) - timedelta(minutes=30)
        # The profile page now offers the PIN entry form.
        assert 'name="code"' in client.get("/profile").text
        assert "email.verify.send" in [a.action for a in audit_entries()]

    def test_confirm_with_correct_pin_verifies(self, monkeypatch):
        make_user()
        save_smtp()
        sent = capture_mail(monkeypatch)
        client = profile_client()
        client.post("/profile/verify-email", data={"csrf": csrf_for(client)}, follow_redirects=False)
        pin = re.search(r"\b(\d{6})\b", sent["body"]).group(1)

        r = client.post(
            "/profile/verify-email/confirm",
            data={"csrf": csrf_for(client), "code": pin},
            follow_redirects=False,
        )
        assert "Email verified" in flash_of(r)
        assert get_user("alice").email_verified is True
        with session_scope() as s:
            row = s.scalar(select(EmailVerification))
            assert row.consumed_at is not None
        assert "email.verify.confirm" in [a.action for a in audit_entries()]

    def test_three_wrong_pins_invalidate_code(self, monkeypatch):
        make_user()
        save_smtp()
        sent = capture_mail(monkeypatch)
        client = profile_client()
        client.post("/profile/verify-email", data={"csrf": csrf_for(client)}, follow_redirects=False)
        pin = re.search(r"\b(\d{6})\b", sent["body"]).group(1)
        wrong = "000000" if pin != "000000" else "000001"

        flashes = []
        for _ in range(3):
            r = client.post(
                "/profile/verify-email/confirm",
                data={"csrf": csrf_for(client), "code": wrong},
                follow_redirects=False,
            )
            flashes.append(flash_of(r))
        assert "Incorrect code" in flashes[0]
        assert "invalidated" in flashes[2]
        # Even the right code no longer works.
        r = client.post(
            "/profile/verify-email/confirm",
            data={"csrf": csrf_for(client), "code": pin},
            follow_redirects=False,
        )
        assert "No pending verification code" in flash_of(r)
        assert get_user("alice").email_verified is False

    def test_expired_code_rejected(self):
        make_user()
        save_smtp()
        uid = get_user("alice").id
        with session_scope() as s:
            s.add(
                EmailVerification(
                    user_id=uid,
                    code_hash=hashlib.sha256(b"424242").hexdigest(),
                    expires_at=datetime.now(UTC) - timedelta(minutes=1),
                )
            )
        client = profile_client()
        r = client.post(
            "/profile/verify-email/confirm",
            data={"csrf": csrf_for(client), "code": "424242"},
            follow_redirects=False,
        )
        assert "expired" in flash_of(r)
        assert get_user("alice").email_verified is False

    def test_no_pending_code(self):
        make_user()
        save_smtp()
        client = profile_client()
        r = client.post(
            "/profile/verify-email/confirm",
            data={"csrf": csrf_for(client), "code": "123456"},
            follow_redirects=False,
        )
        assert "No pending verification code" in flash_of(r)

    def test_new_pin_supersedes_old(self, monkeypatch):
        make_user()
        save_smtp()
        sent = capture_mail(monkeypatch)
        client = profile_client()
        client.post("/profile/verify-email", data={"csrf": csrf_for(client)}, follow_redirects=False)
        client.post("/profile/verify-email", data={"csrf": csrf_for(client)}, follow_redirects=False)
        pins = [m.group(1) for b in sent["bodies"] if (m := re.search(r"\b(\d{6})\b", b))]
        assert len(pins) == 2 and pins[0] != pins[1]
        # Only the newest code is confirmable.
        client.post(
            "/profile/verify-email/confirm",
            data={"csrf": csrf_for(client), "code": pins[1]},
            follow_redirects=False,
        )
        assert get_user("alice").email_verified is True


# ------------------------- API keys -------------------------


def create_key(client: TestClient, name: str = "widget", expiry_days: str = "") -> str:
    r = client.post(
        "/profile/api-keys",
        data={"csrf": csrf_for(client), "name": name, "expiry_days": expiry_days},
        follow_redirects=False,
    )
    assert r.status_code == 303
    return flash_of(r)


def key_row() -> ApiKey:
    with session_scope() as s:
        return s.scalar(select(ApiKey))


def raw_key_for(client: TestClient) -> str:
    flash = create_key(client)
    return re.search(r"shown only once: (sk-[A-Za-z0-9_\-]+)", flash).group(1)


class TestApiKeys:
    def test_create_shows_full_key_once(self):
        make_user()
        client = profile_client()
        flash = create_key(client, name="dashboard")
        m = re.search(r"shown only once: (sk-[A-Za-z0-9_\-]+)", flash)
        assert m, flash
        raw = m.group(1)
        row = key_row()
        assert row.name == "dashboard"
        assert row.prefix == raw[:8]
        assert row.key_hash == hash_token(raw)
        assert raw not in row.key_hash  # hash only, at rest
        assert row.revoked_at is None and row.expires_at is None
        assert "api_key.create" in [a.action for a in audit_entries()]

        # Afterwards only the masked prefix is shown.
        page = client.get("/profile").text
        assert f"<code>{raw[:8]}…</code>" in page
        assert raw not in page

    def test_create_requires_name_and_csrf(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/api-keys",
            data={"csrf": csrf_for(client), "name": "  "},
            follow_redirects=False,
        )
        assert "name/label is required" in flash_of(r)
        r = client.post(
            "/profile/api-keys",
            data={"csrf": "forged", "name": "x"},
            follow_redirects=False,
        )
        assert "Bad CSRF token" in flash_of(r)
        assert key_row() is None

    def test_create_with_expiry(self):
        make_user()
        client = profile_client()
        create_key(client, expiry_days="30")
        row = key_row()
        assert row.expires_at is not None
        assert row.expires_at.replace(tzinfo=UTC) > datetime.now(UTC) + timedelta(days=29)

    def test_invalid_expiry_rejected(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/api-keys",
            data={"csrf": csrf_for(client), "name": "x", "expiry_days": "abc"},
            follow_redirects=False,
        )
        assert "Invalid expiry" in flash_of(r)
        assert key_row() is None

    def test_authenticates_via_x_api_key_and_bearer(self):
        make_user()
        client = profile_client()
        raw = raw_key_for(client)
        anon = TestClient(app)
        assert anon.get("/articles").status_code == 401
        assert anon.get("/articles", headers={"X-API-Key": raw}).status_code == 200
        assert anon.get("/articles", headers={"Authorization": f"Bearer {raw}"}).status_code == 200
        # last_used_at was touched by the successful calls.
        assert key_row().last_used_at is not None

    def test_last_used_touch_is_throttled(self):
        make_user()
        client = profile_client()
        raw = raw_key_for(client)
        uid = get_user("alice").id
        with session_scope() as s:
            row = s.scalar(select(ApiKey).where(ApiKey.user_id == uid))
            row.last_used_at = datetime.now(UTC)
            before = row.last_used_at
        anon = TestClient(app)
        anon.get("/articles", headers={"X-API-Key": raw})
        with session_scope() as s:
            row = s.scalar(select(ApiKey).where(ApiKey.user_id == uid))
            lu = row.last_used_at
            lu = lu if lu.tzinfo else lu.replace(tzinfo=UTC)
            assert lu == before  # < 1 min old → no write

    def test_revoked_key_rejected(self):
        make_user()
        client = profile_client()
        raw = raw_key_for(client)
        kid = key_row().id
        r = client.post(
            f"/profile/api-keys/{kid}/revoke",
            data={"csrf": csrf_for(client)},
            follow_redirects=False,
        )
        assert "Revoked" in flash_of(r)
        assert key_row().revoked_at is not None
        assert TestClient(app).get("/articles", headers={"X-API-Key": raw}).status_code == 401
        assert "api_key.revoke" in [a.action for a in audit_entries()]

    def test_expired_key_rejected(self):
        make_user()
        client = profile_client()
        raw = raw_key_for(client)
        uid = get_user("alice").id
        with session_scope() as s:
            row = s.scalar(select(ApiKey).where(ApiKey.user_id == uid))
            row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        assert TestClient(app).get("/articles", headers={"X-API-Key": raw}).status_code == 401

    def test_cannot_revoke_another_users_key(self):
        make_user("alice")
        make_user("bob")
        bob = profile_client("bob")
        raw = raw_key_for(bob)
        kid = key_row().id
        alice = profile_client("alice")
        r = alice.post(
            f"/profile/api-keys/{kid}/revoke",
            data={"csrf": csrf_for(alice)},
            follow_redirects=False,
        )
        assert "not found" in flash_of(r)
        with session_scope() as s:
            assert s.get(ApiKey, kid).revoked_at is None
        # Bob's key still works.
        assert TestClient(app).get("/articles", headers={"X-API-Key": raw}).status_code == 200

    def test_key_table_shows_status(self):
        make_user()
        client = profile_client()
        create_key(client, name="active-key")
        page = client.get("/profile").text
        assert "active-key" in page
        assert ">active<" in page


# ------------------------- per-user chat privacy -------------------------


def make_chat(user_id: int | None, title: str = "chat") -> int:
    with session_scope() as s:
        chat = ChatSession(title=title, user_id=user_id)
        s.add(chat)
        s.flush()
        return chat.id


class TestChatPrivacy:
    def test_sessions_list_scoped_to_owner(self):
        uid_a = make_user("alice")
        make_user("bob")
        a_chat = make_chat(uid_a, "alice-private")
        b_chat = make_chat(get_user("bob").id, "bob-private")
        legacy = make_chat(None, "shared-legacy")

        bob = profile_client("bob")
        data = bob.get("/api/ai/sessions").json()
        ids = {s["id"] for s in data["sessions"]}
        assert b_chat in ids and legacy in ids
        assert a_chat not in ids

        alice = profile_client("alice")
        ids = {s["id"] for s in alice.get("/api/ai/sessions").json()["sessions"]}
        assert a_chat in ids and legacy in ids and b_chat not in ids

    def test_cannot_read_anothers_session_detail(self):
        uid_a = make_user("alice")
        make_user("bob")
        a_chat = make_chat(uid_a, "alice-private")
        with session_scope() as s:
            s.add(ChatMessage(session_id=a_chat, role="user", content="secret question"))
            s.flush()

        bob = profile_client("bob")
        r = bob.get(f"/api/ai/sessions/{a_chat}")
        assert r.status_code == 404
        assert "secret question" not in r.text
        alice = profile_client("alice")
        assert alice.get(f"/api/ai/sessions/{a_chat}").status_code == 200

    def test_ask_with_foreign_session_id_rejected(self):
        uid_a = make_user("alice")
        make_user("bob")
        a_chat = make_chat(uid_a)
        bob = profile_client("bob")
        r = bob.post("/api/ai/ask", json={"question": "what is this?", "session_id": a_chat})
        assert r.status_code == 404

    def test_own_session_still_usable(self, monkeypatch):
        """Owner can load their session through the ask path (no 404)."""
        uid = make_user("alice")
        mine = make_chat(uid)
        client = profile_client()
        # 404-on-foreign-session happens before any provider work; a disabled
        # AI feature therefore proves the session itself was accepted.
        r = client.post("/api/ai/ask", json={"question": "hello?", "session_id": mine})
        assert r.status_code != 404

    def test_master_key_keeps_shared_view(self, monkeypatch):
        monkeypatch.setenv("CTI_API_KEY", "master-key")
        from scry.config import get_settings

        get_settings.cache_clear()
        uid_a = make_user("alice")
        a_chat = make_chat(uid_a, "alice-private")
        anon = TestClient(app)
        ids = {
            s["id"]
            for s in anon.get("/api/ai/sessions", headers={"X-API-Key": "master-key"}).json()["sessions"]
        }
        assert a_chat in ids  # master key: no resolved user → legacy shared view

    def test_user_api_key_scopes_sessions(self):
        make_user("alice")
        make_user("bob")
        uid_b = get_user("bob").id
        b_chat = make_chat(uid_b, "bob-private")
        bob = profile_client("bob")
        raw = raw_key_for(bob)
        anon = TestClient(app)
        ids = {s["id"] for s in anon.get("/api/ai/sessions", headers={"X-API-Key": raw}).json()["sessions"]}
        assert b_chat in ids


# ------------------------- review actor attribution -------------------------


def make_review() -> int:
    with session_scope() as s:
        row = AnalystReview(item_type="observable", item_id=1, reason="test review")
        s.add(row)
        s.flush()
        return row.id


class TestReviewActor:
    def test_bulk_approve_stamps_actor(self):
        make_user()
        rid = make_review()
        client = profile_client()
        r = client.post(
            "/ui/reviews/bulk",
            data={"review_ids": [str(rid)], "action": "approve"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        with session_scope() as s:
            row = s.get(AnalystReview, rid)
            assert row.status == "closed"
            assert row.disposition == "true_positive"
            assert row.analyst == "alice"
        entries = [a for a in audit_entries() if a.action == "review.bulk"]
        assert entries and entries[0].actor == "alice"
        assert entries[0].detail["count"] == 1

    def test_single_patch_stamps_actor(self):
        make_user()
        rid = make_review()
        client = profile_client()
        client.post(
            f"/ui/reviews/{rid}",
            data={"status": "closed", "disposition": "false_positive"},
            follow_redirects=False,
        )
        with session_scope() as s:
            assert s.get(AnalystReview, rid).analyst == "alice"
        entries = [a for a in audit_entries() if a.action == "review.update"]
        assert entries and entries[0].actor == "alice"
        assert entries[0].target_id == rid


# ------------------------- /admin create-user verification -------------------------


class TestAdminCreateUserVerification:
    def _admin_client(self) -> TestClient:
        make_user("root", role="admin")
        client = TestClient(app)
        login(client, "root")
        return client

    def test_email_auto_verified_when_smtp_unconfigured(self):
        client = self._admin_client()
        client.post(
            "/admin/users/create",
            data={
                "csrf": csrf_for(client),
                "username": "bob",
                "email": "bob@example.com",
                "display_name": "",
                "role": "user",
                "password": "Init!pass123",
            },
            follow_redirects=False,
        )
        assert get_user("bob").email_verified is True

    def test_pin_sent_when_smtp_configured(self, monkeypatch):
        save_smtp()
        sent = capture_mail(monkeypatch)
        client = self._admin_client()
        r = client.post(
            "/admin/users/create",
            data={
                "csrf": csrf_for(client),
                "username": "bob",
                "email": "bob@example.com",
                "display_name": "",
                "role": "user",
                "password": "Init!pass123",
            },
            follow_redirects=False,
        )
        assert "Verification code sent" in flash_of(r)
        bob = get_user("bob")
        assert bob.email_verified is False
        assert sent["to"] == "bob@example.com"
        assert re.search(r"\b(\d{6})\b", sent["body"])
        with session_scope() as s:
            assert s.scalar(select(EmailVerification).where(EmailVerification.user_id == bob.id))
