"""Fernet key-location tests: the ``CTI_SECRET_FILE`` override.

Container/installed deployments put the package in read-only site-packages, so
the default key path (next to the package) is unwritable there; the override
relocates the auto-generated key onto a writable volume.
"""

from __future__ import annotations

import stat

from scry import crypto


class TestSecretPath:
    def test_env_override_roundtrip(self, monkeypatch, tmp_path):
        key_file = tmp_path / "keys" / "secret.key"
        key_file.parent.mkdir()
        monkeypatch.setenv("CTI_SECRET_FILE", str(key_file))

        token = crypto.encrypt("sk-test-123")
        assert crypto.decrypt(token) == "sk-test-123"

        # Key materialized at the override path, owner-only permissions, and
        # reused (not rotated) between the encrypt and decrypt calls above.
        assert crypto._secret_path() == key_file
        assert key_file.exists()
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

    def test_default_when_env_unset(self, monkeypatch):
        monkeypatch.delenv("CTI_SECRET_FILE", raising=False)
        assert crypto._secret_path() == crypto._SECRET_PATH
        assert crypto._SECRET_PATH.name == ".cti_secret"

    def test_override_empty_string_falls_back(self, monkeypatch):
        # An empty override is treated as unset (defensive against
        # `CTI_SECRET_FILE=` in env files).
        monkeypatch.setenv("CTI_SECRET_FILE", "")
        assert crypto._secret_path() == crypto._SECRET_PATH
