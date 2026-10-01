"""Backup / restore for scry installs (v0.8.0 step 1).

One-command move of an install between machines: the code comes from git,
this covers the DATA. A backup is a tar.gz archive with a ``manifest.json``
(scry version, creation time, database kind, table counts, sha256 checksums
of every archived file). ``--full`` additionally includes ``data/`` and the
downloaded AI search model; ``--encrypt`` Fernet-encrypts the archive with
the install's existing ``.cti_secret`` key.

Archive contents ALWAYS include secrets (.env, .cti_secret, feed keys) —
treat every backup as sensitive.

NOTE: run backup/restore with the scry server STOPPED. SQLite has no safe
hot-backup story here; copying a live DB file can silently produce a corrupt
or torn archive.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import InvalidToken
from sqlalchemy import create_engine, func, inspect, select

from scry import crypto
from scry.config import REPO_ROOT, get_settings
from scry.models import CVE, Alert, AnalystReview, Article, Observable, Source

# The tables counted here mirror `scry stats` in scry/cli.py — keep in sync.


class BackupError(Exception):
    """User-facing backup/restore failure (CLI prints + exits non-zero)."""


def installed_version() -> str:
    """Version of the installed scry (same string the FastAPI app reports)."""
    from scry.main import app as fastapi_app

    return fastapi_app.version or "0.0.0"


def _version_tuple(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for tok in version.strip().split("."):
        digits = "".join(ch for ch in tok if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _is_newer(version_a: str, version_b: str) -> bool:
    a, b = _version_tuple(version_a), _version_tuple(version_b)
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) > b + (0,) * (n - len(b))


def resolve_db_path() -> Path:
    """Resolve the SQLite DB file from Settings; refuse other backends."""
    from sqlalchemy.engine import make_url

    url = get_settings().database_url
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        raise BackupError(
            f"Backup supports SQLite installs only (CTI_DATABASE_URL={url!r} looks like a "
            "server database — not supported). Use pg_dump / your Postgres backup tooling instead."
        )
    raw = parsed.database or ""
    if not raw or raw == ":memory:":
        raise BackupError("CTI_DATABASE_URL points at an in-memory database — nothing to back up.")
    path = Path(raw)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def table_counts_session(session) -> dict[str, int]:
    """Row counts for the `scry stats` tables, using an ORM session."""
    return {
        "sources": int(session.scalar(select(func.count(Source.id))) or 0),
        "articles": int(session.scalar(select(func.count(Article.id))) or 0),
        "observables": int(session.scalar(select(func.count(Observable.id))) or 0),
        "cves": int(session.scalar(select(func.count(CVE.id))) or 0),
        "alerts": int(session.scalar(select(func.count(Alert.id))) or 0),
        "open_reviews": int(
            session.scalar(select(func.count(AnalystReview.id)).where(AnalystReview.status == "open")) or 0
        ),
    }


def _table_counts_file(db_path: Path) -> dict[str, int]:
    """Row counts for the `scry stats` tables, reading a SQLite file directly."""
    engine = create_engine(f"sqlite+pysqlite:///{db_path}", future=True)
    # (stats key, table, optional WHERE) — mirrors `scry stats` exactly.
    queries = [
        ("sources", "sources", None),
        ("articles", "articles", None),
        ("observables", "observables", None),
        ("cves", "cves", None),
        ("alerts", "alerts", None),
        ("open_reviews", "analyst_reviews", "status = 'open'"),
    ]
    try:
        from sqlalchemy import text

        tables = set(inspect(engine).get_table_names())
        out: dict[str, int] = {}
        with engine.connect() as conn:
            for key, table, where in queries:
                if table not in tables:
                    out[key] = -1  # table absent in this DB
                    continue
                sql = f"SELECT count(*) FROM {table}" + (f" WHERE {where}" if where else "")
                out[key] = int(conn.scalar(text(sql)) or 0)
        return out
    finally:
        engine.dispose()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_files(full: bool) -> list[tuple[Path, str]]:
    """(source path, archive name) pairs for the backup."""
    settings = get_settings()
    cwd = Path.cwd()
    files: list[tuple[Path, str]] = []
    seen: set[str] = set()

    def add(path: Path, arcname: str) -> None:
        if arcname in seen or not path.is_file():
            return
        seen.add(arcname)
        files.append((path, arcname))

    add(resolve_db_path(), resolve_db_path().name)

    for name in (".env", ".cti_secret"):
        add(cwd / name, name)

    config_dir = Path(settings.config_dir)
    if config_dir.is_dir():
        for p in sorted(config_dir.glob("*.yaml")):
            add(p, f"config/{p.name}")

    # Alembic version stamp: the ini plus every migration script.
    add(REPO_ROOT / "alembic.ini", "alembic.ini")
    versions_dir = REPO_ROOT / "alembic" / "versions"
    if versions_dir.is_dir():
        for p in sorted(versions_dir.glob("*.py")):
            add(p, f"alembic/versions/{p.name}")

    if full:
        data_dir = cwd / "data"
        if data_dir.is_dir():
            for p in sorted(data_dir.rglob("*")):
                if p.is_file():
                    add(p, str(p.relative_to(cwd)))
        model = Path(settings.ai_search_model_path)
        if not model.is_absolute():
            model = cwd / model
        add(model, str(model.relative_to(cwd)) if model.is_relative_to(cwd) else model.name)

    return files


def _write_tar(files: list[tuple[Path, str]], manifest: dict[str, Any], output: Path) -> None:
    with tarfile.open(output, "w:gz") as tf:
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest_bytes)
        info.mtime = int(datetime.now(tz=UTC).timestamp())
        tf.addfile(info, io.BytesIO(manifest_bytes))
        for src, arcname in files:
            tf.add(src, arcname=arcname, recursive=False)


def create_backup(output: Path | None, full: bool, encrypt: bool) -> Path:
    """Create a backup archive; returns the final archive path."""
    db_path = resolve_db_path()
    if not db_path.is_file():
        raise BackupError(f"Database file not found: {db_path} — nothing to back up.")

    from scry.db import session_scope

    with session_scope() as session:
        counts = table_counts_session(session)

    files = _collect_files(full)
    manifest: dict[str, Any] = {
        "scry_version": installed_version(),
        "created_at": datetime.now(tz=UTC).isoformat(),
        "database": {"kind": "sqlite", "file": db_path.name},
        "table_counts": counts,
        "full": full,
        "files": {arcname: {"sha256": _sha256(src), "size": src.stat().st_size} for src, arcname in files},
    }

    if output is None:
        output = Path(f"scry-backup-{datetime.now(tz=UTC):%Y%m%d}.tar.gz")
    output = Path(output)

    _write_tar(files, manifest, output)

    if encrypt:
        if not crypto._SECRET_PATH.exists():
            raise BackupError(
                f"Encryption requested but no Fernet key at {crypto._SECRET_PATH}. "
                "Run any encrypting command once (e.g. `scry users create`) to generate .cti_secret."
            )
        token = crypto.get_fernet().encrypt(output.read_bytes())
        enc_path = output.with_name(output.name + ".enc")
        enc_path.write_bytes(token)
        output.unlink()
        output = enc_path

    return output


def _safe_members(tf: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = []
    for member in tf.getmembers():
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise BackupError(f"Archive contains unsafe path {name!r} — refusing to extract.")
        if member.isreg() or member.isdir():
            members.append(member)
        elif member.issym() or member.islnk() or member.isdev():
            raise BackupError(f"Archive contains a link/device entry {name!r} — refusing to extract.")
    return members


def _read_archive_bytes(archive: Path) -> bytes:
    data = archive.read_bytes()
    if str(archive).endswith(".enc"):
        if not crypto._SECRET_PATH.exists():
            raise BackupError(
                f"{archive} is encrypted and the Fernet key file {crypto._SECRET_PATH} is "
                "missing. Restore needs the .cti_secret from the machine that made the backup."
            )
        try:
            return crypto.get_fernet().decrypt(data)
        except InvalidToken as exc:
            raise BackupError(
                f"Could not decrypt {archive}: the local .cti_secret key does not match the "
                "key that encrypted it."
            ) from exc
    return data


def _destination_for(arcname: str, db_name: str, target: Path) -> Path:
    if arcname == db_name:
        return target / db_name
    if arcname.startswith(("config/", "data/", "alembic/")):
        return target / arcname
    return target / arcname  # .env, .cti_secret, alembic.ini


def _atomic_copy(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f".{dest.name}.tmp-{os.getpid()}")
    try:
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()


def restore_backup(archive: Path, force: bool, target_dir: Path) -> dict[str, Any]:
    """Restore an archive into target_dir; returns a summary dict."""
    archive = Path(archive)
    if not archive.is_file():
        raise BackupError(f"Archive not found: {archive}")
    target = Path(target_dir)

    data = _read_archive_bytes(archive)
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = _safe_members(tf)
            tmpdir = Path(tempfile.mkdtemp(prefix="scry-restore-"))
            tf.extractall(tmpdir, members=members)
    except tarfile.TarError as exc:
        raise BackupError(f"{archive} is not a readable scry backup archive: {exc}") from exc

    manifest_path = tmpdir / "manifest.json"
    if not manifest_path.is_file():
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise BackupError("Archive has no manifest.json — not a scry backup (refusing to restore).")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise BackupError(f"manifest.json is invalid JSON: {exc}") from exc

    files_meta: dict[str, dict[str, Any]] = manifest.get("files") or {}
    if not isinstance(files_meta, dict) or not files_meta:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise BackupError("manifest.json has no file checksums — refusing to restore.")

    # Verify every declared file exists and matches its recorded checksum.
    corrupted: list[str] = []
    for arcname, meta in files_meta.items():
        extracted = tmpdir / arcname
        if not extracted.is_file():
            corrupted.append(f"{arcname} (missing)")
            continue
        if _sha256(extracted) != meta.get("sha256"):
            corrupted.append(f"{arcname} (checksum mismatch)")
    if corrupted:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise BackupError(
            "Archive failed integrity checks — file(s) missing or tampered: "
            + ", ".join(sorted(corrupted))
            + ". Restore aborted."
        )

    archive_version = str(manifest.get("scry_version") or "0.0.0")
    current = installed_version()
    if _is_newer(archive_version, current) and not force:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise BackupError(
            f"This backup was made with scry {archive_version}, which is NEWER than the "
            f"installed version {current}. Restoring it may write a database this version "
            "cannot read. Re-run with --force to override."
        )

    db_name = str((manifest.get("database") or {}).get("file") or "cti.sqlite")
    db_target = target / db_name
    counts_before: dict[str, int] | None = None
    if db_target.exists():
        if not force:
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise BackupError(
                f"Refusing to overwrite existing database {db_target} — it holds the current "
                "install's data and would be LOST. Re-run with --force to replace it."
            )
        if db_target.is_file():
            counts_before = _table_counts_file(db_target)

    restored: list[str] = []
    for arcname in files_meta:
        _atomic_copy(tmpdir / arcname, _destination_for(arcname, db_name, target))
        restored.append(arcname)
    shutil.rmtree(tmpdir, ignore_errors=True)

    counts_after: dict[str, int] | None = None
    if db_target.is_file():
        counts_after = _table_counts_file(db_target)

    return {
        "archive": str(archive),
        "target": str(target),
        "scry_version": archive_version,
        "installed_version": current,
        "restored": sorted(restored),
        "manifest_counts": manifest.get("table_counts") or {},
        "counts_before": counts_before,
        "counts_after": counts_after,
    }
