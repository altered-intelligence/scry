"""SQLite FTS5 full-text index layer.

FTS5 tables mirror the four searchable object types (articles, observables,
entities, claims). They are regular FTS5 tables (FTS5 owns its copy of the
indexed text), kept in sync incrementally by the write paths (ingestion,
pipeline, OTX pulses) and created/backfilled by the startup migration
(``scry.migrations``).

Design notes:
- Feature-detected: when the SQLite build lacks FTS5 (or the tables have not
  been created yet — e.g. non-SQLite backends) every helper here is a no-op
  and ``full_text_search`` falls back to the legacy LIKE scan.
- Regular (content-owning) FTS5 tables are used deliberately: with
  external-content tables, a row DELETE or REPLACE after the content changed
  resolves tokens through the *new* content and silently corrupts the index
  ("database disk image is malformed"). Regular tables make
  ``INSERT OR REPLACE`` and ``DELETE`` exact and safe at any time, at the cost
  of storing the indexed text twice (acceptable for the indexed columns).
"""

from __future__ import annotations

from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from scry.logging import get_logger

logger = get_logger("search.fts")

# kind -> (fts table, content table, indexed columns)
FTS_TABLES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "article": ("articles_fts", "articles", ("title", "extracted_text", "summary")),
    "observable": ("observables_fts", "observables", ("normalized_value",)),
    "entity": ("entities_fts", "entities", ("canonical_name", "aliases")),
    "claim": ("claims_fts", "claims", ("claim_text", "evidence_text")),
}

_TOKENIZER = "porter unicode61"
_BATCH = 1000
_IN_CHUNK = 500  # stay well under SQLite's variable limit

# Per-engine memo of "FTS tables exist and are queryable". Keyed by id(bind);
# entries are dropped on any OperationalError at query time and on explicit
# invalidation (tests, teardown), so stale ids never stick.
_READY: dict[int, bool] = {}


def fts5_supported(conn: Connection) -> bool:
    """True when this SQLite build has the FTS5 module (temp-table probe)."""
    if conn.dialect.name != "sqlite":
        return False
    try:
        conn.exec_driver_sql("CREATE VIRTUAL TABLE temp._fts5_probe USING fts5(x)")
        conn.exec_driver_sql("DROP TABLE temp._fts5_probe")
        return True
    except Exception:
        return False


def _table_exists(conn: Connection, table: str) -> bool:
    return bool(
        conn.exec_driver_sql(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).scalar()
    )


def ensure_fts_tables(conn: Connection) -> bool:
    """Create the FTS5 tables when missing. Returns True when the index is usable."""
    if conn.dialect.name != "sqlite":
        return False
    if not fts5_supported(conn):
        logger.info("fts5_unavailable", msg="SQLite FTS5 module not found — LIKE search stays active")
        return False
    for fts_table, _content_table, cols in FTS_TABLES.values():
        if _table_exists(conn, fts_table):
            continue
        collist = ", ".join(cols)
        conn.exec_driver_sql(
            f"CREATE VIRTUAL TABLE {fts_table} USING fts5({collist}, tokenize='{_TOKENIZER}')"
        )
        logger.info("fts_table_created", table=fts_table)
    return True


def fts_ready(session: Session) -> bool:
    """True (memoized) when the FTS tables exist on this session's SQLite bind."""
    bind = session.get_bind()
    if bind.dialect.name != "sqlite":
        return False
    key = id(bind)
    ready = _READY.get(key)
    if ready is None:
        ready = _table_exists(session.connection(), FTS_TABLES["article"][0])
        _READY[key] = ready
    return ready


def fts_invalidate(session: Session) -> None:
    """Forget the memoized readiness for this session's bind."""
    _READY.pop(id(session.get_bind()), None)


def _clean(value) -> str:
    return "" if value is None else str(value)


def _populate(
    conn: Connection, fts_table: str, content_table: str, cols: tuple[str, ...], *, only_missing: bool
) -> int:
    """Batch-insert content rows into the FTS index. Returns rows indexed."""
    collist = ", ".join(cols)
    placeholders = ", ".join("?" for _ in range(len(cols) + 1))
    missing_clause = f"WHERE id NOT IN (SELECT rowid FROM {fts_table})" if only_missing else ""
    inserted = 0
    last_id = 0
    while True:
        rows = conn.exec_driver_sql(
            (
                f"SELECT id, {collist} FROM {content_table} "
                f"{missing_clause} AND id > ? ORDER BY id LIMIT ?"
                if missing_clause
                else f"SELECT id, {collist} FROM {content_table} WHERE id > ? ORDER BY id LIMIT ?"
            ),
            (last_id, _BATCH),
        ).all()
        if not rows:
            break
        conn.exec_driver_sql(
            f"INSERT INTO {fts_table}(rowid, {collist}) VALUES ({placeholders})",
            [(r[0], *[_clean(v) for v in r[1:]]) for r in rows],
        )
        inserted += len(rows)
        last_id = rows[-1][0]
    return inserted


def backfill_fts(conn: Connection) -> dict[str, int]:
    """Index rows missing from the FTS tables; purge orphaned index entries.

    Idempotent and batched — safe to run on every startup against large
    databases. Orphaned index entries (content row gone) are removed
    directly; with unindex-before-delete in the write paths this is a rare
    repair.
    """
    counts: dict[str, int] = {}
    for kind, (fts_table, content_table, cols) in FTS_TABLES.items():
        if not _table_exists(conn, fts_table) or not _table_exists(conn, content_table):
            counts[kind] = 0
            continue
        conn.exec_driver_sql(f"DELETE FROM {fts_table} WHERE rowid NOT IN (SELECT id FROM {content_table})")
        counts[kind] = _populate(conn, fts_table, content_table, cols, only_missing=True)
        if counts[kind]:
            logger.info("fts_backfilled", table=fts_table, rows=counts[kind])
    return counts


def rebuild_fts(session: Session) -> dict[str, int]:
    """Full rebuild of every FTS table from current content. Returns per-kind counts."""
    counts: dict[str, int] = {}
    if not fts_ready(session):
        return counts
    conn = session.connection()
    for kind, (fts_table, content_table, cols) in FTS_TABLES.items():
        conn.exec_driver_sql(f"DELETE FROM {fts_table}")
        counts[kind] = _populate(conn, fts_table, content_table, cols, only_missing=False)
    logger.info("fts_rebuilt", **counts)
    return counts


def index_rows(session: Session, kind: str, rowids: list[int]) -> int:
    """Upsert FTS entries for the given content rows (INSERT OR REPLACE).

    Reads the current content values and re-indexes them. Rows that no
    longer exist are skipped (their stale entries are unreachable through
    the query-time JOIN and get purged by the next backfill). Never raises —
    indexing must not break the write path it rides on. Does NOT commit; the
    caller's transaction carries the index writes.
    """
    if not rowids:
        return 0
    try:
        if not fts_ready(session):
            return 0
        fts_table, content_table, cols = FTS_TABLES[kind]
        collist = ", ".join(cols)
        insert_ph = ", ".join("?" for _ in range(len(cols) + 1))
        conn = session.connection()
        indexed = 0
        for i in range(0, len(rowids), _IN_CHUNK):
            chunk = rowids[i : i + _IN_CHUNK]
            ph = ", ".join("?" for _ in chunk)
            rows = conn.exec_driver_sql(
                f"SELECT id, {collist} FROM {content_table} WHERE id IN ({ph})", tuple(chunk)
            ).all()
            for r in rows:
                conn.exec_driver_sql(
                    f"INSERT OR REPLACE INTO {fts_table}(rowid, {collist}) VALUES ({insert_ph})",
                    (r[0], *[_clean(v) for v in r[1:]]),
                )
                indexed += 1
        return indexed
    except Exception as exc:  # pragma: no cover - defensive: never break writes
        logger.warning("fts_index_failed", kind=kind, exc=str(exc))
        return 0


def unindex_claims_for_article(session: Session, article_id: int) -> None:
    """Remove FTS entries for an article's claims — BEFORE they are deleted.

    Kept ahead of the claim DELETE in pipeline reprocessing so the index can
    never accumulate stale claim entries even if a future schema change
    touches the FTS layout.
    """
    try:
        if not fts_ready(session):
            return
        session.connection().exec_driver_sql(
            "DELETE FROM claims_fts WHERE rowid IN (SELECT id FROM claims WHERE article_id = ?)",
            (article_id,),
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("fts_unindex_failed", article_id=article_id, exc=str(exc))
