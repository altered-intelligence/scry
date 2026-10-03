"""Lightweight schema migrations (v0.5.0 step 3).

The project DOES ship alembic (``alembic/versions/0001_initial.py``), but the
app does not depend on it at runtime: ``Base.metadata.create_all`` only
creates NEW tables, so adding a column to an EXISTING table needs an explicit
ALTER TABLE here. Each migration is checked against the live schema with the
SQLAlchemy inspector and skipped when already present, so ``run_migrations()``
is idempotent and safe to run on every startup. Run it right after
``create_all`` (see ``scry.main._ensure_db_ready`` and the ``scry init-db``
CLI). Alembic's initial revision calls the same ``apply_migrations()`` after
its own ``create_all`` so both schema paths converge on the same columns and
indexes.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from scry.db import get_engine
from scry.logging import get_logger

logger = get_logger("migrations")


@dataclass(frozen=True)
class AddColumn:
    """Add ``column`` to ``table`` when it is not already there."""

    table: str
    column: str
    ddl: str


# Append-only. Keep DDL plain (no IF NOT EXISTS — SQLite lacks it); presence
# is decided by the inspector check in apply_migrations().
MIGRATIONS: tuple[AddColumn, ...] = (
    AddColumn(
        table="chat_sessions",
        column="user_id",
        ddl="ALTER TABLE chat_sessions ADD COLUMN user_id INTEGER",
    ),
    AddColumn(
        table="users",
        column="totp_pending",
        ddl="ALTER TABLE users ADD COLUMN totp_pending BOOLEAN NOT NULL DEFAULT 0",
    ),
    # v0.4.0 step 6 introduced connector_settings.api_key_encrypted via
    # create_all only — existing databases never got the column (the code's
    # defensive fallback masked it). Backfill it here.
    AddColumn(
        table="connector_settings",
        column="api_key_encrypted",
        ddl="ALTER TABLE connector_settings ADD COLUMN api_key_encrypted VARCHAR",
    ),
    # v0.8.0 step 2 — EPSS percentile + enrichment timestamp; create_all only
    # covers fresh databases, existing ones need the explicit ALTER.
    AddColumn(
        table="cves",
        column="epss_percentile",
        ddl="ALTER TABLE cves ADD COLUMN epss_percentile FLOAT",
    ),
    AddColumn(
        table="cves",
        column="epss_enriched_at",
        ddl="ALTER TABLE cves ADD COLUMN epss_enriched_at DATETIME",
    ),
)

# Hot-path indexes. Fresh databases get these from the model metadata
# (``index=True``); CREATE INDEX IF NOT EXISTS backfills existing databases.
# Names match SQLAlchemy's default ix_<table>_<column> convention so both
# paths produce the same index name. Entries are (table, column, ddl) so
# partial legacy databases skip indexes whose column they don't have.
INDEXES: tuple[tuple[str, str, str], ...] = (
    (
        "observables",
        "risk_score",
        "CREATE INDEX IF NOT EXISTS ix_observables_risk_score ON observables (risk_score)",
    ),
    (
        "observables",
        "status",
        "CREATE INDEX IF NOT EXISTS ix_observables_status ON observables (status)",
    ),
    ("cves", "kev", "CREATE INDEX IF NOT EXISTS ix_cves_kev ON cves (kev)"),
    (
        "articles",
        "ingested_at",
        "CREATE INDEX IF NOT EXISTS ix_articles_ingested_at ON articles (ingested_at)",
    ),
    (
        "source_fetches",
        "fetched_at",
        "CREATE INDEX IF NOT EXISTS ix_source_fetches_fetched_at ON source_fetches (fetched_at)",
    ),
)


def apply_migrations(conn: Connection) -> None:
    """Apply pending column ALTERs and index backfills on an open connection."""
    inspector = inspect(conn)
    for migration in MIGRATIONS:
        if not inspector.has_table(migration.table):
            continue
        existing = {c["name"] for c in inspector.get_columns(migration.table)}
        if migration.column in existing:
            continue
        conn.execute(text(migration.ddl))
    for table, column, ddl in INDEXES:
        if not inspector.has_table(table):
            continue
        if column not in {c["name"] for c in inspector.get_columns(table)}:
            continue
        conn.execute(text(ddl))
    _apply_fts(conn)


def _apply_fts(conn: Connection) -> None:
    """Create + backfill the FTS5 search index (SQLite only, best-effort).

    v0.9.0: FTS5 replaces leading-wildcard LIKE scans for full-text search.
    Never block startup on the index — the LIKE fallback keeps search working.
    """
    if conn.dialect.name != "sqlite":
        return
    try:
        from scry.search.fts import backfill_fts, ensure_fts_tables

        if ensure_fts_tables(conn):
            backfill_fts(conn)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("fts_migration_failed", exc=str(exc))


def run_migrations() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        apply_migrations(conn)
