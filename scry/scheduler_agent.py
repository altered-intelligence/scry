"""launchd LaunchAgent management for the Scry scheduler (macOS).

``scry scheduler install`` writes ``com.scry.scheduler.plist`` into
``~/Library/LaunchAgents`` so the APScheduler process (``python -m
scry.scheduler``) runs unattended: started at login, restarted on crash,
logs under ``<repo>/logs/`` (gitignored via ``*.log``). Nothing is loaded
into launchd by this module — the printed ``launchctl bootstrap`` command
is left to the owner (or ``--load``).

The plist records the venv interpreter, the project working directory (so
``.env`` and relative config resolve), and an absolute ``CTI_DATABASE_URL``
when the configured one is the default relative SQLite path.

Linux is out of scope here — see docs/scheduling.md for a systemd unit.
"""

from __future__ import annotations

import plistlib
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from scry.config import REPO_ROOT, get_settings

LABEL = "com.scry.scheduler"
DEFAULT_AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"
LOG_DIR = REPO_ROOT / "logs"


@dataclass
class InstallResult:
    plist_path: Path
    action: str  # "installed" | "updated" | "unchanged"
    log_dir: Path


def _abs_database_url() -> str:
    """Absolute CTI_DATABASE_URL for the launchd environment.

    launchd jobs get a bare environment; the default relative SQLite path
    (``sqlite+pysqlite:///./cti.sqlite``) is anchored at the repo root so
    the agent always opens the same database regardless of cwd quirks.
    """
    url = get_settings().database_url
    prefix = "sqlite+pysqlite:///"
    if url.startswith(prefix):
        path = url[len(prefix) :]
        p = Path(path)
        if not p.is_absolute():
            p = (REPO_ROOT / p).resolve()
        return prefix + str(p)
    return url


def build_plist() -> dict:
    """The LaunchAgent plist as a dict (plistlib-serializable)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, "-m", "scry.scheduler"],
        "WorkingDirectory": str(REPO_ROOT),
        "EnvironmentVariables": {
            "CTI_DATABASE_URL": _abs_database_url(),
            "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin",
        },
        "StandardOutPath": str(LOG_DIR / "scheduler.log"),
        "StandardErrorPath": str(LOG_DIR / "scheduler.err.log"),
        "RunAtLoad": True,
        "KeepAlive": True,
    }


def install(agents_dir: Path = DEFAULT_AGENTS_DIR) -> InstallResult:
    """Write the plist (idempotent). Returns what happened."""
    agents_dir = Path(agents_dir).expanduser()
    agents_dir.mkdir(parents=True, exist_ok=True)
    plist_path = agents_dir / f"{LABEL}.plist"
    payload = plistlib.dumps(build_plist())
    if plist_path.exists():
        if plist_path.read_bytes() == payload:
            return InstallResult(plist_path, "unchanged", LOG_DIR)
        plist_path.write_bytes(payload)
        return InstallResult(plist_path, "updated", LOG_DIR)
    plist_path.write_bytes(payload)
    return InstallResult(plist_path, "installed", LOG_DIR)


def uninstall(agents_dir: Path = DEFAULT_AGENTS_DIR) -> Path | None:
    """Remove the plist. Returns the removed path, or None when absent."""
    plist_path = Path(agents_dir).expanduser() / f"{LABEL}.plist"
    if not plist_path.exists():
        return None
    plist_path.unlink()
    return plist_path


def status(agents_dir: Path = DEFAULT_AGENTS_DIR) -> dict:
    """Installed/loaded state plus digest readiness — read-only."""
    plist_path = Path(agents_dir).expanduser() / f"{LABEL}.plist"
    loaded = bool(shutil.which("launchctl")) and _launchctl_loaded()
    settings = get_settings()
    return {
        "label": LABEL,
        "plist_path": str(plist_path),
        "installed": plist_path.exists(),
        "loaded_in_launchd": loaded,
        "digest_email_enabled": settings.digest_email_enabled,
        "digest_email_to": settings.digest_email_to,
        "digest_email_hour": settings.digest_email_hour,
        "log_out": str(LOG_DIR / "scheduler.log"),
        "log_err": str(LOG_DIR / "scheduler.err.log"),
    }


def _launchctl_loaded() -> bool:
    """True when launchd currently knows the label (best-effort, no raise)."""
    import os
    import subprocess

    try:
        res = subprocess.run(
            ["launchctl", "print", f"gui/{os.getuid()}/{LABEL}"],
            capture_output=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False
