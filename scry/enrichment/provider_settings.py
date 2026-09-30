"""External IOC-enrichment provider configuration.

Per-provider state lives in the ``connector_settings`` table (encrypted API
key + enable toggle), managed from the Alerts page panel via
``GET/PUT /enrichment/providers``. When no DB row exists for a provider,
the matching ``CTI_*_API_KEY`` env var from ``scry.config.Settings`` is the
fallback key and the provider defaults to enabled (key present ⇒ active).

Reads are defensive: databases created before the ``api_key_encrypted``
column existed would otherwise 500 the whole settings surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.exc import OperationalError, ProgrammingError
from sqlalchemy.orm import Session

from scry.config import get_settings
from scry.crypto import decrypt, mask
from scry.logging import get_logger
from scry.models import ConnectorSetting

logger = get_logger("enrichment")

# provider name → static metadata + the Settings field used as env fallback.
PROVIDER_META: dict[str, dict[str, Any]] = {
    "virustotal": {"display_name": "VirusTotal", "env_field": "virustotal_api_key"},
    "otx": {"display_name": "AlienVault OTX", "env_field": "otx_api_key"},
    "abuseipdb": {"display_name": "AbuseIPDB", "env_field": "abuseipdb_api_key"},
    "greynoise": {"display_name": "GreyNoise", "env_field": "greynoise_api_key"},
}


@dataclass
class ProviderState:
    name: str
    display_name: str
    enabled: bool  # toggle state (row.enabled; defaults True when no row)
    api_key: str  # effective key (DB row wins over env)
    api_key_source: str  # "db" | "env" | ""
    configured: bool  # a connector_settings row exists
    last_check_at: Any = None
    last_check_ok: bool | None = None
    last_check_error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key_present(self) -> bool:
        return bool(self.api_key)

    @property
    def api_key_masked(self) -> str:
        return mask(self.api_key) if self.api_key else "—"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.name,
            "display_name": self.display_name,
            "enabled": self.enabled,
            "configured": self.configured,
            "api_key_masked": self.api_key_masked,
            "api_key_source": self.api_key_source,
            "key_present": self.key_present,
            "last_check_at": self.last_check_at.isoformat() if self.last_check_at else None,
            "last_check_ok": self.last_check_ok,
            "last_check_error": self.last_check_error,
        }


def _load_rows(session: Session) -> dict[str, ConnectorSetting]:
    try:
        rows = session.query(ConnectorSetting).all()
    except (OperationalError, ProgrammingError) as exc:
        # Pre-existing DB without the api_key_encrypted column: fall back to
        # env-only config instead of breaking the settings surface.
        logger.warning("connector_settings_unreadable", error=str(exc))
        return {}
    return {r.provider: r for r in rows}


def load_provider_states(session: Session) -> dict[str, ProviderState]:
    """Effective config for every supported external enrichment provider."""
    rows = _load_rows(session)
    settings = get_settings()
    states: dict[str, ProviderState] = {}
    for name, meta in PROVIDER_META.items():
        row = rows.get(name)
        db_key = decrypt(row.api_key_encrypted) if row else ""
        env_key = getattr(settings, meta["env_field"], "") or ""
        if db_key:
            key, source = db_key, "db"
        elif env_key:
            key, source = env_key, "env"
        else:
            key, source = "", ""
        states[name] = ProviderState(
            name=name,
            display_name=meta["display_name"],
            enabled=(row.enabled if row is not None else True),
            api_key=key,
            api_key_source=source,
            configured=row is not None,
            last_check_at=row.last_check_at if row else None,
            last_check_ok=row.last_check_ok if row else None,
            last_check_error=row.last_check_error if row else None,
        )
    return states


def selected_providers(
    states: dict[str, ProviderState], providers: list[str] | None
) -> tuple[dict[str, ProviderState], dict[str, str]]:
    """Apply the `providers` filter and split into runnable / skipped.

    Returns (runnable, skipped) where skipped maps provider name → reason.
    Raises ValueError on unknown provider names.
    """
    if providers:
        unknown = [p for p in providers if p not in states]
        if unknown:
            raise ValueError(
                f"Unknown enrichment provider(s): {', '.join(sorted(unknown))}. "
                f"Supported: {', '.join(sorted(states))}"
            )
        wanted = dict.fromkeys(providers)
    else:
        wanted = dict.fromkeys(states)

    runnable: dict[str, ProviderState] = {}
    skipped: dict[str, str] = {}
    for name in wanted:
        state = states[name]
        if not state.enabled:
            skipped[name] = "disabled"
        elif not state.api_key:
            skipped[name] = "no api key"
        else:
            runnable[name] = state
    return runnable, skipped
