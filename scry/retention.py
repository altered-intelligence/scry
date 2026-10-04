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

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session

from scry.extraction.relationship_extractor import MAX_EVIDENCE_CHARS, evidence_window
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


# ------------------------- relationship evidence cap -------------------------

# Relationship endpoints that live in the entities table; every other kind is
# an observable type (mirrors the resolution in scry.pipeline / scry.exports).
_ENTITY_KINDS = {
    "threat_actor",
    "malware_family",
    "tool",
    "campaign",
    "intrusion_set",
    "organization",
    "person",
    "sector",
    "location",
    "vulnerability",
}
_EVIDENCE_BATCH = 50  # rows per round trip — oversized rows can be hundreds of KB each


def truncate_relationship_evidence(
    target: Session | Connection,
    max_chars: int = MAX_EVIDENCE_CHARS,
    *,
    dry_run: bool = False,
) -> dict:
    """Window oversized ``relationships.evidence_text`` down to ``max_chars``.

    Extractions made before the evidence cap stored the whole surrounding
    "sentence" on every relationship row; punctuation-free inputs (pasted
    IOC sheets) turned that into hundreds of KB per row. Each oversized row
    is re-windowed around its two endpoints with the same ``evidence_window``
    new extractions use, so repaired rows look exactly like fresh ones.
    Idempotent — a second run finds nothing to do. ``dry_run`` reports the
    candidate count and a reclaim estimate without writing. Does NOT commit:
    the caller's transaction (``session_scope`` / ``engine.begin()``) carries
    the writes, and the file only shrinks after a VACUUM (see the CLI).
    """
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    conn = target.connection() if isinstance(target, Session) else target
    candidates, bytes_before = conn.exec_driver_sql(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(evidence_text)), 0) "
        "FROM relationships WHERE LENGTH(evidence_text) > ?",
        (max_chars,),
    ).one()
    candidates, bytes_before = int(candidates), int(bytes_before)
    result = {
        "max_chars": max_chars,
        "candidates": candidates,
        "truncated": 0,
        "bytes_before": bytes_before,
        "bytes_after": bytes_before,
        # Estimate until rows are rewritten: every candidate shrinks to <= max_chars.
        "bytes_reclaimed": max(0, bytes_before - candidates * max_chars),
    }
    if dry_run or not candidates:
        logger.info("relationship_evidence_trim", dry_run=dry_run, **result)
        return result

    ids = [
        int(r[0])
        for r in conn.exec_driver_sql(
            "SELECT id FROM relationships WHERE LENGTH(evidence_text) > ? ORDER BY id", (max_chars,)
        ).all()
    ]
    labels: dict[tuple[str, int], list[str]] = {}
    truncated = 0
    bytes_after = 0
    for start in range(0, len(ids), _EVIDENCE_BATCH):
        chunk = ids[start : start + _EVIDENCE_BATCH]
        ph = ", ".join("?" for _ in chunk)
        rows = conn.exec_driver_sql(
            "SELECT id, source_type, source_id, target_type, target_id, evidence_text "
            f"FROM relationships WHERE id IN ({ph})",
            tuple(chunk),
        ).all()
        updates: list[tuple[str, int]] = []
        for rid, src_type, src_id, tgt_type, tgt_id, text in rows:
            endpoints = [
                _endpoint_labels(conn, src_type, src_id, labels),
                _endpoint_labels(conn, tgt_type, tgt_id, labels),
            ]
            trimmed = evidence_window(text or "", endpoints, max_chars=max_chars)
            bytes_after += len(trimmed)
            updates.append((trimmed, int(rid)))
        if updates:
            conn.exec_driver_sql("UPDATE relationships SET evidence_text = ? WHERE id = ?", updates)
            truncated += len(updates)

    result.update(truncated=truncated, bytes_after=bytes_after, bytes_reclaimed=bytes_before - bytes_after)
    logger.info("relationship_evidence_trimmed", **result)
    return result


def _endpoint_labels(
    conn: Connection, kind: str, oid: int, cache: dict[tuple[str, int], list[str]]
) -> list[str]:
    """Surface forms a relationship endpoint may appear as in evidence text (cached)."""
    key = (kind, int(oid))
    if key in cache:
        return cache[key]
    labels: list[str] = []
    if kind in _ENTITY_KINDS:
        row = conn.exec_driver_sql(
            "SELECT canonical_name, aliases FROM entities WHERE id = ?", (oid,)
        ).first()
        if row is not None:
            labels.append(str(row[0] or ""))
            raw = row[1]
            try:
                aliases = json.loads(raw) if isinstance(raw, str) else list(raw or [])
            except (TypeError, ValueError):
                aliases = []
            labels.extend(str(a) for a in aliases)
    else:
        row = conn.exec_driver_sql(
            "SELECT value, normalized_value FROM observables WHERE id = ?", (oid,)
        ).first()
        if row is not None:
            labels.extend(str(v or "") for v in row)
    cache[key] = [label for label in labels if label]
    return cache[key]
