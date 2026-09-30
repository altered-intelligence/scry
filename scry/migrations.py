"""Lightweight schema migrations (v0.5.0 step 3).

The project has no alembic; ``Base.metadata.create_all`` only creates NEW
tables, so adding a column to an EXISTING table needs an explicit ALTER TABLE
here. Each migration is checked against the live schema with the SQLAlchemy
inspector and skipped when already present, so ``run_migrations()`` is
idempotent and safe to run on every startup. Run it right after
``create_all`` (see ``scry.main._ensure_db_ready`` and the ``scry init-db``
CLI).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect, text

from scry.db import get_engine


@dataclass(frozen=True)
class AddColumn:
    """Add ``column`` to ``table`` when it is not already there."""

    table: str
    column: str
    ddl: str


# Append-only. Keep DDL plain (no IF NOT EXISTS — SQLite lacks it); presence
# is decided by the inspector check in run_migrations().
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
)


def run_migrations() -> None:
    engine = get_engine()
    inspector = inspect(engine)
    with engine.begin() as conn:
        for migration in MIGRATIONS:
            existing = {c["name"] for c in inspector.get_columns(migration.table)}
            if migration.column in existing:
                continue
            conn.execute(text(migration.ddl))
