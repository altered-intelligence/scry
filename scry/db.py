"""Database engine + session factory.

Single source of truth for engine creation. Uses SQLAlchemy 2.x style.
SQLite is supported for tests and zero-infra runs; Postgres+pgvector for
production.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import String, cast, create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from scry.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def tag_filter(column, tag: str):
    """Match a single tag inside a JSON array column (SQLite-safe).

    ``Column.contains([tag])`` on a JSON column compiles to a LIKE pattern
    that includes the array brackets, so it only matches single-element
    arrays. Match the *quoted* tag string instead — every JSON encoding of a
    string list contains ``"tag"``. LIKE metacharacters in the tag are
    escaped so tags containing ``%`` or ``_`` match literally.
    """
    escaped = tag.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return cast(column, String).like(f'%"{escaped}"%', escape="\\")


def get_engine() -> Engine:
    global _engine, _SessionLocal
    if _engine is None:
        url = get_settings().database_url
        connect_args: dict = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _engine = create_engine(url, future=True, connect_args=connect_args, pool_pre_ping=True)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False)

        if url.startswith("sqlite"):

            @event.listens_for(_engine, "connect")
            def _enable_sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                # WAL + a busy timeout let the API, scheduler, and CLI share
                # one SQLite file without "database is locked" failures.
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=5000")
                cur.close()

    return _engine


def session_factory() -> sessionmaker:
    get_engine()
    assert _SessionLocal is not None
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    factory = session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine_for_tests() -> None:
    """Force recreation. Tests use this when they switch DATABASE_URL."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
