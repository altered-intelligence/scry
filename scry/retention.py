"""raw_html retention pruning (v0.14.0).

``Article.raw_html`` dominates database size but is only needed to RE-parse an
article (full-content fetch); every consumer — FTS, embeddings, extraction,
exports, UI — works off ``extracted_text``. Pruning nulls ``raw_html`` for
articles older than the configured retention while keeping the row,
``extracted_text``, and all derived data. A pruned article that later needs
its HTML is re-fetched from its URL by ``fetch_full_content`` (which already
selects on ``raw_html IS NULL`` — the graceful-degradation path).

Age is anchored on ``ingested_at`` (when WE stored the HTML), falling back to
``published_at``; articles with neither are never pruned.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from scry.logging import get_logger
from scry.models import Article

logger = get_logger("retention")


def prune_raw_html(
    session: Session,
    retention_days: int,
    *,
    dry_run: bool = False,
    now: datetime | None = None,
) -> dict:
    """Null ``raw_html`` for articles older than ``retention_days``.

    ``retention_days <= 0`` disables pruning entirely (keep forever).
    ``dry_run`` reports what WOULD be pruned without writing. Returns a dict:
    ``enabled``, ``cutoff``, ``candidates``, ``pruned``, ``bytes_reclaimed``
    (approximate — character count of the nulled HTML, ~bytes for the
    overwhelmingly-ASCII markup we store).
    """
    if retention_days <= 0:
        logger.info("raw_html_prune_skipped", reason="retention disabled (0 = keep forever)")
        return {"enabled": False, "cutoff": None, "candidates": 0, "pruned": 0, "bytes_reclaimed": 0}

    cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    age = func.coalesce(Article.ingested_at, Article.published_at)
    # NULL age sorts NULL < cutoff → excluded automatically; only rows that
    # still HAVE html and are provably older than the horizon qualify.
    where = [Article.raw_html.is_not(None), age < cutoff]

    candidates, bytes_reclaimed = session.execute(
        select(func.count(Article.id), func.coalesce(func.sum(func.length(Article.raw_html)), 0)).where(
            *where
        )
    ).one()

    pruned = 0
    if not dry_run and candidates:
        pruned = session.execute(update(Article).where(*where).values(raw_html=None)).rowcount or 0
        session.flush()

    logger.info(
        "raw_html_prune",
        dry_run=dry_run,
        cutoff=cutoff.isoformat(),
        candidates=candidates,
        pruned=pruned,
        bytes_reclaimed=bytes_reclaimed,
    )
    return {
        "enabled": True,
        "cutoff": cutoff,
        "candidates": candidates,
        "pruned": pruned,
        "bytes_reclaimed": bytes_reclaimed,
    }


def vacuum_sqlite(engine: Engine) -> bool:
    """Reclaim freed pages after a prune. SQLite-only and best-effort —
    a running app holding the write lock turns this into a logged skip,
    never a failure. Returns True when the VACUUM ran."""
    if not engine.url.get_backend_name().startswith("sqlite"):
        return False
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.exec_driver_sql("VACUUM")
        logger.info("raw_html_vacuum_done")
        return True
    except Exception as exc:  # database is locked, etc.
        logger.warning("raw_html_vacuum_skipped", exc=str(exc))
        return False


def human_bytes(n: int | float) -> str:
    """Format a byte count for CLI output (1024-based, one decimal)."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} TB"  # pragma: no cover — unreachable
