"""Tests for `scry backup` / `scry restore` (v0.8.0 step 1).

All tests run inside a scratch install dir (tmp_path) with monkeypatched
CWD / Settings / crypto secret path — the real cti.sqlite, .env and
.cti_secret in the repo are never touched.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from typer.testing import CliRunner

from scry import backup as backup_mod
from scry import crypto
from scry.cli import app as cli_app

runner = CliRunner()


@pytest.fixture
def install(tmp_path, monkeypatch):
    """A scratch scry install: CWD, config dir, DB URL and Fernet key all isolated."""
    root = tmp_path / "install"
    root.mkdir()
    (root / "config").mkdir()
    (root / "config" / "sources.yaml").write_text("sources: []\n", encoding="utf-8")
    (root / "config" / "watchlists.yaml").write_text("watchlists: []\n", encoding="utf-8")
    (root / ".env").write_text("CTI_ENV=test\n", encoding="utf-8")
    (root / ".cti_secret").write_bytes(Fernet.generate_key())
    (root / "cti.sqlite").write_bytes(b"")  # replaced by real schema below

    monkeypatch.chdir(root)
    monkeypatch.setenv("CTI_DATABASE_URL", f"sqlite+pysqlite:///{root}/cti.sqlite")
    monkeypatch.setenv("CTI_CONFIG_DIR", str(root / "config"))
    monkeypatch.setattr(crypto, "_SECRET_PATH", root / ".cti_secret")

    from scry import config as config_mod
    from scry import db as db_mod
    from scry.db import get_engine
    from scry.models.base import Base

    config_mod.get_settings.cache_clear()
    db_mod.reset_engine_for_tests()
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return root


_seed_n = 0


def _seed_counts() -> dict[str, int]:
    """Insert one row per stats table; returns expected counts."""
    from sqlalchemy import func, select

    from scry.db import session_scope
    from scry.models import CVE, Alert, AnalystReview, Article, Observable, Source

    global _seed_n
    _seed_n += 1
    n = _seed_n
    with session_scope() as s:
        s.add(Source(name=f"S{n}", type="vendor_blog", url=f"https://e.test/{n}", enabled=True))
        s.add(Article(url=f"https://e.test/{n}/1", source_id=1, title="t"))
        s.add(Observable(type="ip", value=f"1.2.3.{n}", normalized_value=f"1.2.3.{n}"))
        s.add(CVE(cve_id=f"CVE-2024-{n:04d}"))
        s.add(Alert(trigger="test", severity="low", title=f"a{n}"))
        s.add(AnalystReview(item_type="observable", item_id=1, status="open", reason=f"r{n}"))
        s.flush()
        out = {
            "sources": int(s.scalar(select(func.count(Source.id)))),
            "articles": int(s.scalar(select(func.count(Article.id)))),
            "observables": int(s.scalar(select(func.count(Observable.id)))),
            "cves": int(s.scalar(select(func.count(CVE.id)))),
            "alerts": int(s.scalar(select(func.count(Alert.id)))),
            "open_reviews": int(s.scalar(select(func.count(AnalystReview.id)))),
        }
    return out


def _make_archive(path: Path, files: dict[str, bytes], manifest: dict) -> None:
    with tarfile.open(path, "w:gz") as tf:
        manifest_bytes = json.dumps(manifest).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest_bytes)
        tf.addfile(info, io.BytesIO(manifest_bytes))
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


# ------------------------------- backup -------------------------------


def test_backup_creates_valid_archive_with_manifest(install):
    counts = _seed_counts()
    out = install / "b.tar.gz"
    r = runner.invoke(cli_app, ["backup", "--output", str(out)])
    assert r.exit_code == 0, r.output
    assert out.is_file()
    assert "secrets" in r.output.lower()

    with tarfile.open(out, "r:gz") as tf:
        names = tf.getnames()
        assert "manifest.json" in names
        assert "cti.sqlite" in names
        assert ".env" in names
        assert ".cti_secret" in names
        assert "config/sources.yaml" in names
        assert "config/watchlists.yaml" in names
        manifest = json.loads(tf.extractfile("manifest.json").read())

    assert manifest["database"]["kind"] == "sqlite"
    assert manifest["table_counts"] == counts
    for meta in manifest["files"].values():
        assert len(meta["sha256"]) == 64


def test_backup_default_name_in_cwd(install):
    _seed_counts()
    r = runner.invoke(cli_app, ["backup"])
    assert r.exit_code == 0, r.output
    defaults = list(install.glob("scry-backup-*.tar.gz"))
    assert len(defaults) == 1


def test_backup_refuses_non_sqlite(install, monkeypatch):
    monkeypatch.setenv("CTI_DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    from scry import config as config_mod

    config_mod.get_settings.cache_clear()
    r = runner.invoke(cli_app, ["backup", "--output", str(install / "b.tar.gz")])
    assert r.exit_code == 1
    assert "not supported" in r.output


def test_backup_full_includes_data_dir(install):
    _seed_counts()
    data_file = install / "data" / "raw" / "page.html"
    data_file.parent.mkdir(parents=True)
    data_file.write_text("<html></html>", encoding="utf-8")
    out = install / "full.tar.gz"
    r = runner.invoke(cli_app, ["backup", "--output", str(out), "--full"])
    assert r.exit_code == 0, r.output
    with tarfile.open(out, "r:gz") as tf:
        assert "data/raw/page.html" in tf.getnames()


# ------------------------------- encrypt / round-trip -------------------------------


def test_backup_encrypt_round_trip(install):
    counts = _seed_counts()
    out = install / "enc.tar.gz.enc"
    r = runner.invoke(cli_app, ["backup", "--output", str(install / "enc.tar.gz"), "--encrypt"])
    assert r.exit_code == 0, r.output
    assert out.is_file()
    # Not a plaintext tar.
    assert not tarfile.is_tarfile(out)

    target = install / "restored"
    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(target)])
    assert r.exit_code == 0, r.output
    db = target / "cti.sqlite"
    assert db.is_file()
    assert backup_mod._table_counts_file(db) == counts
    assert (target / ".env").read_bytes() == b"CTI_ENV=test\n"
    assert (target / "config" / "sources.yaml").is_file()


def test_restore_encrypted_without_key_errors(install, monkeypatch):
    _seed_counts()
    out = install / "enc.tar.gz.enc"
    r = runner.invoke(cli_app, ["backup", "--output", str(install / "enc.tar.gz"), "--encrypt"])
    assert r.exit_code == 0, r.output
    # Remove the key entirely.
    (install / ".cti_secret").unlink()
    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(install / "r")])
    assert r.exit_code == 1
    assert "key" in r.output.lower()


def test_restore_encrypted_with_wrong_key_errors(install, monkeypatch):
    _seed_counts()
    out = install / "enc.tar.gz.enc"
    r = runner.invoke(cli_app, ["backup", "--output", str(install / "enc.tar.gz"), "--encrypt"])
    assert r.exit_code == 0, r.output
    (install / ".cti_secret").write_bytes(Fernet.generate_key())
    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(install / "r")])
    assert r.exit_code == 1
    assert "decrypt" in r.output.lower()


# ------------------------------- restore -------------------------------


def test_restore_refuses_overwrite_without_force(install):
    _seed_counts()
    out = install / "b.tar.gz"
    assert runner.invoke(cli_app, ["backup", "--output", str(out)]).exit_code == 0
    # Add more data AFTER the backup so "before" counts differ.
    _seed_counts()

    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(install)])
    assert r.exit_code == 1
    assert "Refusing to overwrite" in r.output
    assert "--force" in r.output

    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(install), "--force"])
    assert r.exit_code == 0, r.output
    assert "before → after" in r.output
    # Two sources were inserted total; backup held one → restored DB has one.
    assert backup_mod._table_counts_file(install / "cti.sqlite")["sources"] == 1


def test_restore_refuses_newer_version_without_force(install):
    counts = _seed_counts()
    db_bytes = (install / "cti.sqlite").read_bytes()
    manifest = {
        "scry_version": "99.0.0",
        "created_at": "2030-01-01T00:00:00+00:00",
        "database": {"kind": "sqlite", "file": "cti.sqlite"},
        "table_counts": counts,
        "files": {
            "cti.sqlite": {"sha256": backup_mod._sha256(install / "cti.sqlite"), "size": len(db_bytes)}
        },
    }
    archive = install / "newer.tar.gz"
    _make_archive(archive, {"cti.sqlite": db_bytes}, manifest)

    target = install / "r"
    r = runner.invoke(cli_app, ["restore", str(archive), "--target-dir", str(target)])
    assert r.exit_code == 1
    assert "NEWER" in r.output
    assert not (target / "cti.sqlite").exists()

    r = runner.invoke(cli_app, ["restore", str(archive), "--target-dir", str(target), "--force"])
    assert r.exit_code == 0, r.output
    assert (target / "cti.sqlite").is_file()


def test_restore_rejects_tampered_archive(install):
    _seed_counts()
    db_bytes = (install / "cti.sqlite").read_bytes()
    manifest = {
        "scry_version": backup_mod.installed_version(),
        "created_at": "2026-01-01T00:00:00+00:00",
        "database": {"kind": "sqlite", "file": "cti.sqlite"},
        "table_counts": {},
        "files": {
            "cti.sqlite": {"sha256": backup_mod._sha256(install / "cti.sqlite"), "size": len(db_bytes)}
        },
    }
    archive = install / "tampered.tar.gz"
    _make_archive(archive, {"cti.sqlite": b"garbage-bytes"}, manifest)

    r = runner.invoke(cli_app, ["restore", str(archive), "--target-dir", str(install / "r")])
    assert r.exit_code == 1
    assert "checksum" in r.output.lower()


def test_restore_rejects_archive_without_manifest(install):
    _seed_counts()
    out = install / "nomanifest.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        data = b"x"
        info = tarfile.TarInfo("cti.sqlite")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(install / "r")])
    assert r.exit_code == 1
    assert "manifest" in r.output.lower()


def test_restore_summary_shows_manifest_counts(install):
    counts = _seed_counts()
    out = install / "b.tar.gz"
    assert runner.invoke(cli_app, ["backup", "--output", str(out)]).exit_code == 0
    target = install / "r"
    r = runner.invoke(cli_app, ["restore", str(out), "--target-dir", str(target)])
    assert r.exit_code == 0, r.output
    for value in counts.values():
        assert f"{value} → {value}" in r.output


def test_restore_rejects_path_traversal(install):
    _seed_counts()
    manifest = {
        "scry_version": backup_mod.installed_version(),
        "database": {"kind": "sqlite", "file": "cti.sqlite"},
        "files": {
            "../evil.sqlite": {"sha256": hashlib.sha256(b"evil").hexdigest(), "size": 4},
        },
    }
    archive = install / "evil.tar.gz"
    _make_archive(archive, {"../evil.sqlite": b"evil"}, manifest)
    r = runner.invoke(cli_app, ["restore", str(archive), "--target-dir", str(install / "r")])
    assert r.exit_code == 1
    assert not (install / "evil.sqlite").exists()
