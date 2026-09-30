"""Tests for v0.5.0 step 5: WebAuthn passkeys.

Follows the test_mfa.py pattern: real HTTP calls through TestClient against
an isolated SQLite DB. Real attestation/assertion signatures cannot be
faked without an authenticator, so the ``verify_registration_response`` /
``verify_authentication_response`` functions are monkeypatched at the
``scry.auth.webauthn`` module boundary (where the routes look them up) and
return objects shaped like webauthn's VerifiedRegistration /
VerifiedAuthentication. Everything else — routes, pending markers, sessions,
audit, rp_id derivation — is exercised for real.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from freezegun import freeze_time
from sqlalchemy import func, select

from scry.auth import webauthn as webauthn_helpers
from scry.auth.passwords import hash_password
from scry.auth.sessions import SESSION_COOKIE
from scry.db import session_scope
from scry.main import _admin_csrf_token, app
from scry.models import AuditLog, PasskeyCredential, User

PASSWORD = "S3cure!pass"
CRED_ID_1 = b"fake-credential-id-1"
CRED_ID_2 = b"fake-credential-id-2"
PUBLIC_KEY = b"\xa5\x01\x02\x03& \x01"  # pretend COSE key
AAGUID = "adce0002-35bc-c60a-648b-0b25f1f05503"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_user(username: str = "alice", password: str = PASSWORD, role: str = "user") -> int:
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


def passkey_rows(username: str = "alice") -> list[PasskeyCredential]:
    uid = get_user(username).id
    with session_scope() as s:
        return list(s.scalars(select(PasskeyCredential).where(PasskeyCredential.user_id == uid)))


def audit_entries() -> list[AuditLog]:
    with session_scope() as s:
        return list(s.scalars(select(AuditLog)))


def login(client: TestClient, username: str = "alice", password: str = PASSWORD):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def profile_client(username: str = "alice") -> TestClient:
    client = TestClient(app)
    login(client, username)
    return client


def csrf_for(client: TestClient) -> str:
    return _admin_csrf_token(client.cookies[SESSION_COOKIE])


def flash_of(response) -> str:
    return parse_qs(urlparse(response.headers["location"]).query)["flash"][0]


def fake_registration_credential(cred_id: bytes = CRED_ID_1) -> dict:
    """The JSON shape navigator.credentials.create() POSTs back."""
    return {
        "id": b64u(cred_id),
        "rawId": b64u(cred_id),
        "type": "public-key",
        "response": {
            "attestationObject": b64u(b"fake-attestation-object"),
            "clientDataJSON": b64u(b'{"type":"webauthn.create"}'),
        },
        "clientExtensionResults": {},
        "transports": ["internal", "usb"],
    }


def fake_authentication_credential(cred_id: bytes = CRED_ID_1) -> dict:
    """The JSON shape navigator.credentials.get() POSTs back."""
    return {
        "id": b64u(cred_id),
        "rawId": b64u(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(b'{"type":"webauthn.get"}'),
            "authenticatorData": b64u(b"fake-authenticator-data"),
            "signature": b64u(b"fake-signature"),
            "userHandle": None,
        },
        "clientExtensionResults": {},
    }


class FakeVerifiedRegistration:
    """Shape-compatible with webauthn's VerifiedRegistration (v2/v3 stable fields)."""

    def __init__(self, cred_id: bytes = CRED_ID_1, sign_count: int = 0):
        self.credential_id = cred_id
        self.credential_public_key = PUBLIC_KEY
        self.sign_count = sign_count
        self.aaguid = AAGUID


class FakeVerifiedAuthentication:
    """Shape-compatible with webauthn's VerifiedAuthentication."""

    def __init__(self, cred_id: bytes = CRED_ID_1, new_sign_count: int = 1):
        self.credential_id = cred_id
        self.new_sign_count = new_sign_count


@pytest.fixture
def patch_verify_registration(monkeypatch):
    calls: list[dict] = []

    def _fake(**kwargs):
        calls.append(kwargs)
        cred_id = webauthn_helpers.credential_id_bytes(kwargs["credential"]) or CRED_ID_1
        return FakeVerifiedRegistration(cred_id=cred_id)

    monkeypatch.setattr(webauthn_helpers, "verify_registration_response", _fake)
    return calls


@pytest.fixture
def patch_verify_authentication(monkeypatch):
    calls: list[dict] = []

    def _fake(**kwargs):
        calls.append(kwargs)
        return FakeVerifiedAuthentication(new_sign_count=kwargs["credential_current_sign_count"] + 1)

    monkeypatch.setattr(webauthn_helpers, "verify_authentication_response", _fake)
    return calls


def register_passkey(
    client: TestClient,
    monkeypatch=None,
    name: str = "MacBook Touch ID",
    cred_id: bytes = CRED_ID_1,
    password: str = PASSWORD,
) -> TestClient:
    """Full register begin→complete ceremony against a logged-in client."""
    begin = client.post(
        "/profile/passkeys/register-begin",
        data={"csrf": csrf_for(client), "password": password},
    )
    assert begin.status_code == 200, begin.text
    assert webauthn_helpers.PASSKEY_PENDING_COOKIE in client.cookies
    complete = client.post(
        "/profile/passkeys/register-complete",
        json={"csrf": csrf_for(client), "name": name, "credential": fake_registration_credential(cred_id)},
    )
    assert complete.status_code == 200, complete.text
    assert complete.json()["ok"] is True
    return client


# ------------------------- rp derivation -------------------------


class TestRpDerivation:
    def test_rp_id_strips_port(self):
        assert webauthn_helpers.rp_id_from_host("localhost:7100") == "localhost"
        assert webauthn_helpers.rp_id_from_host("scry.lan:8443") == "scry.lan"
        assert webauthn_helpers.rp_id_from_host("localhost") == "localhost"

    def test_rp_id_ipv6(self):
        assert webauthn_helpers.rp_id_from_host("[::1]:8000") == "::1"

    def test_register_begin_uses_host_rp_id(self):
        make_user()
        client = TestClient(app, base_url="http://localhost:7100")
        login(client)
        r = client.post(
            "/profile/passkeys/register-begin",
            data={"csrf": csrf_for(client), "password": PASSWORD},
        )
        assert r.status_code == 200
        options = r.json()["options"]
        assert options["rp"] == {"name": "Scry", "id": "localhost"}
        assert options["user"]["name"] == "alice"
        assert options["excludeCredentials"] in (None, [])

    def test_register_begin_exclude_list_after_first_passkey(self, patch_verify_registration):
        make_user()
        client = profile_client()
        register_passkey(client, name="first")
        r = client.post(
            "/profile/passkeys/register-begin",
            data={"csrf": csrf_for(client), "password": PASSWORD},
        )
        options = r.json()["options"]
        assert len(options["excludeCredentials"]) == 1
        assert options["excludeCredentials"][0]["id"] == b64u(CRED_ID_1)


# ------------------------- registration ceremony -------------------------


class TestRegistration:
    def test_profile_page_shows_passkeys_section(self):
        make_user()
        page = profile_client().get("/profile").text
        assert "Passkeys" in page
        assert "No passkeys yet." in page
        assert "/profile/passkeys/register-begin" in page

    def test_register_begin_requires_password_and_csrf(self):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/passkeys/register-begin",
            data={"csrf": csrf_for(client), "password": "wrong-pass"},
        )
        assert r.status_code == 403
        assert "Password is incorrect" in r.json()["error"]
        r = client.post(
            "/profile/passkeys/register-begin",
            data={"csrf": "forged", "password": PASSWORD},
        )
        assert r.status_code == 403
        assert "CSRF" in r.json()["error"]
        assert passkey_rows() == []

    def test_register_complete_saves_credential(self, patch_verify_registration):
        make_user()
        client = profile_client()
        register_passkey(client)
        rows = passkey_rows()
        assert len(rows) == 1
        row = rows[0]
        assert row.name == "MacBook Touch ID"
        assert row.credential_id == CRED_ID_1
        assert row.public_key == PUBLIC_KEY
        assert row.sign_count == 0
        assert row.transports == "internal,usb"
        assert row.aaguid == AAGUID
        assert webauthn_helpers.PASSKEY_PENDING_COOKIE not in client.cookies
        actions = [a.action for a in audit_entries()]
        assert "passkey.register" in actions
        # Profile page now lists the passkey.
        page = client.get("/profile").text
        assert "MacBook Touch ID" in page

    def test_register_complete_without_pending_rejected(self, patch_verify_registration):
        make_user()
        client = profile_client()
        r = client.post(
            "/profile/passkeys/register-complete",
            json={
                "csrf": csrf_for(client),
                "name": "nope",
                "credential": fake_registration_credential(),
            },
        )
        assert r.status_code == 400
        assert "expired" in r.json()["error"]
        assert passkey_rows() == []

    def test_register_verify_failure_clears_pending(self, monkeypatch):
        make_user()
        client = profile_client()

        def _raise(**kwargs):
            raise ValueError("registration rejected (e.g. rp_id/origin mismatch)")

        monkeypatch.setattr(webauthn_helpers, "verify_registration_response", _raise)
        begin = client.post(
            "/profile/passkeys/register-begin",
            data={"csrf": csrf_for(client), "password": PASSWORD},
        )
        assert begin.status_code == 200
        r = client.post(
            "/profile/passkeys/register-complete",
            json={
                "csrf": csrf_for(client),
                "name": "x",
                "credential": fake_registration_credential(),
            },
        )
        assert r.status_code == 400
        assert "verification failed" in r.json()["error"]
        assert webauthn_helpers.PASSKEY_PENDING_COOKIE not in client.cookies
        assert passkey_rows() == []

    def test_verify_called_with_request_rp_context(self, patch_verify_registration):
        """The verify call must receive the per-request rp_id and origin."""
        make_user()
        client = TestClient(app, base_url="http://localhost:7100")
        login(client)
        register_passkey(client)
        call = patch_verify_registration[0]
        assert call["expected_rp_id"] == "localhost"
        assert call["expected_origin"] == "http://localhost:7100"
        assert isinstance(call["expected_challenge"], bytes) and call["expected_challenge"]


# ------------------------- rename / delete -------------------------


class TestRenameDelete:
    def test_rename(self, patch_verify_registration):
        make_user()
        client = profile_client()
        register_passkey(client, name="old name")
        row = passkey_rows()[0]
        r = client.post(
            f"/profile/passkeys/{row.id}/rename",
            data={"csrf": csrf_for(client), "name": "YubiKey 5C"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert passkey_rows()[0].name == "YubiKey 5C"
        entry = [a for a in audit_entries() if a.action == "passkey.rename"]
        assert entry and entry[0].detail == {"from": "old name", "to": "YubiKey 5C"}

    def test_rename_other_users_passkey_rejected(self, patch_verify_registration):
        make_user("alice")
        make_user("bob")
        register_passkey(profile_client("bob"), name="bob key")
        alice = profile_client("alice")
        bob_row = passkey_rows("bob")[0]
        r = alice.post(
            f"/profile/passkeys/{bob_row.id}/rename",
            data={"csrf": csrf_for(alice), "name": "hijack"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "not found" in flash_of(r)
        assert passkey_rows("bob")[0].name == "bob key"

    def test_delete_requires_password_and_removes(self, patch_verify_registration):
        make_user()
        client = profile_client()
        register_passkey(client)
        row = passkey_rows()[0]
        r = client.post(
            f"/profile/passkeys/{row.id}/delete",
            data={"csrf": csrf_for(client), "password": "wrong-pass"},
            follow_redirects=False,
        )
        assert "Password is incorrect" in flash_of(r)
        assert len(passkey_rows()) == 1
        r = client.post(
            f"/profile/passkeys/{row.id}/delete",
            data={"csrf": csrf_for(client), "password": PASSWORD},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert passkey_rows() == []
        assert "passkey.delete" in [a.action for a in audit_entries()]


# ------------------------- login ceremony -------------------------


class TestPasskeyLogin:
    def _begin(self, client: TestClient, username: str = "alice"):
        return client.post("/login/passkey/begin", data={"username": username})

    def test_begin_unknown_username_generic_error(self):
        make_user()
        client = TestClient(app)
        r = self._begin(client, "ghost")
        assert r.status_code == 400
        assert "No passkeys are registered" in r.json()["error"]
        assert webauthn_helpers.PASSKEY_PENDING_COOKIE not in client.cookies

    def test_begin_user_without_passkeys_generic_error(self):
        make_user()
        client = TestClient(app)
        r = self._begin(client)
        assert r.status_code == 400
        assert "No passkeys are registered" in r.json()["error"]

    def test_begin_scopes_options_to_user_credentials(self, patch_verify_registration):
        make_user("alice")
        make_user("bob")
        register_passkey(profile_client("alice"), name="a", cred_id=CRED_ID_1)
        register_passkey(profile_client("bob"), name="b", cred_id=CRED_ID_2)
        client = TestClient(app, base_url="http://localhost:7100")
        r = self._begin(client, "alice")
        assert r.status_code == 200
        options = r.json()["options"]
        assert options["rpId"] == "localhost"
        allowed = [c["id"] for c in options["allowCredentials"]]
        assert allowed == [b64u(CRED_ID_1)]
        assert webauthn_helpers.PASSKEY_PENDING_COOKIE in client.cookies

    def test_complete_creates_session(self, patch_verify_registration, patch_verify_authentication):
        make_user()
        register_passkey(profile_client())
        client = TestClient(app, base_url="http://localhost:7100")
        assert self._begin(client).status_code == 200
        r = client.post("/login/passkey/complete", json={"credential": fake_authentication_credential()})
        assert r.status_code == 200
        assert r.json() == {"ok": True, "redirect": "/"}
        assert SESSION_COOKIE in client.cookies
        assert webauthn_helpers.PASSKEY_PENDING_COOKIE not in client.cookies
        assert client.get("/").status_code == 200
        entry = [a for a in audit_entries() if a.action == "login.success"][-1]
        assert entry.detail["via"] == "passkey"
        assert entry.detail["mfa"] == "not_required"
        # Sign counter advanced + last_used_at touched.
        row = passkey_rows()[0]
        assert row.sign_count == 1
        assert row.last_used_at is not None

    def test_complete_honors_next(self, patch_verify_registration, patch_verify_authentication):
        make_user()
        register_passkey(profile_client())
        client = TestClient(app)
        self._begin(client)
        r = client.post(
            "/login/passkey/complete",
            json={"credential": fake_authentication_credential(), "next": "/ui/articles"},
        )
        assert r.json()["redirect"] == "/ui/articles"
        # External next values are refused (same _safe_next as password login).
        client2 = TestClient(app)
        self._begin(client2)
        r = client2.post(
            "/login/passkey/complete",
            json={"credential": fake_authentication_credential(), "next": "https://evil.example"},
        )
        assert r.json()["redirect"] == "/"

    def test_complete_satisfies_mfa(self, patch_verify_registration, patch_verify_authentication):
        """A passkey IS the second factor: totp_enabled users skip /login/mfa."""
        from scry.auth import totp as totp_helpers
        from scry.crypto import encrypt

        # Register the passkey first (profile login is password-only here),
        # then flip MFA on directly in the DB.
        make_user()
        register_passkey(profile_client())
        with session_scope() as s:
            user = s.scalar(select(User).where(func.lower(User.username) == "alice"))
            user.totp_enabled = True
            user.totp_secret_encrypted = encrypt(totp_helpers.generate_secret())
            s.flush()
        client = TestClient(app)
        self._begin(client)
        r = client.post("/login/passkey/complete", json={"credential": fake_authentication_credential()})
        assert r.status_code == 200
        assert SESSION_COOKIE in client.cookies
        entry = [a for a in audit_entries() if a.action == "login.success"][-1]
        assert entry.detail["mfa"] == "satisfied"

    def test_verify_failure_clears_pending_no_session(self, patch_verify_registration, monkeypatch):
        make_user()
        register_passkey(profile_client())
        client = TestClient(app)

        def _raise(**kwargs):
            raise ValueError("assertion rejected (e.g. wrong host/origin)")

        monkeypatch.setattr(webauthn_helpers, "verify_authentication_response", _raise)
        self._begin(client)
        r = client.post("/login/passkey/complete", json={"credential": fake_authentication_credential()})
        assert r.status_code == 400
        assert "verification failed" in r.json()["error"]
        assert SESSION_COOKIE not in client.cookies
        assert webauthn_helpers.PASSKEY_PENDING_COOKIE not in client.cookies
        failures = [a for a in audit_entries() if a.action == "login.failure"]
        assert failures and failures[-1].detail["reason"] == "passkey"

    def test_expired_pending_rejected(self, patch_verify_registration):
        make_user()
        register_passkey(profile_client())
        client = TestClient(app)
        with freeze_time(datetime(2030, 1, 1, 12, 0, tzinfo=UTC)):
            assert self._begin(client).status_code == 200
        with freeze_time(datetime(2030, 1, 1, 12, 6, tzinfo=UTC)):
            r = client.post("/login/passkey/complete", json={"credential": fake_authentication_credential()})
            assert r.status_code == 400
            assert "expired" in r.json()["error"]
            assert SESSION_COOKIE not in client.cookies

    def test_unknown_credential_rejected(self, patch_verify_registration, patch_verify_authentication):
        make_user()
        register_passkey(profile_client())
        client = TestClient(app)
        self._begin(client)
        r = client.post(
            "/login/passkey/complete", json={"credential": fake_authentication_credential(b"other-id")}
        )
        assert r.status_code == 400
        assert r.json()["error"] == "Unknown passkey."
        assert SESSION_COOKIE not in client.cookies


# ------------------------- admin -------------------------


class TestAdminPasskeys:
    def test_users_table_shows_passkey_count(self, patch_verify_registration):
        make_user("alice")
        make_user("root", role="admin")
        register_passkey(profile_client("alice"), name="a")
        admin = TestClient(app)
        login(admin, "root")
        page = admin.get("/admin").text
        assert "<th>Passkeys</th>" in page
        # alice has 1 passkey, root has 0 — counts render per user row.
        import re

        alice_row = re.search(r"<tr>\s*<td><b>alice</b>.*?</tr>", page, re.S)
        assert alice_row and ">1</td>" in alice_row.group(0)
        root_row = re.search(r"<tr>\s*<td><b>root</b>.*?</tr>", page, re.S)
        assert root_row and ">0</td>" in root_row.group(0)
