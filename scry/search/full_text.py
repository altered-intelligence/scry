"""Full-text search.

On SQLite with FTS5 (the default), searches run against the FTS5 index in
``scry.search.fts`` — MATCH queries with ``bm25()`` ranking and ``snippet()``
excerpts. When FTS5 is unavailable (Postgres, old SQLite, or the index not
built yet) the original LIKE scan is used. Both paths return the same
SearchHit shape, so callers (REST /search, UI, MCP, AI retrieval) need no
branching.
"""

from __future__ import annotations

import json

from sqlalchemy import or_, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from scry.logging import get_logger
from scry.models import Article, Claim, Entity, Observable
from scry.schemas.search import SearchHit
from scry.search.fts import fts_invalidate, fts_ready

logger = get_logger("search.full_text")

_ALL_TYPES = ("article", "observable", "entity", "claim")


def full_text_search(
    session: Session, q: str, *, limit: int = 50, types: list[str] | None = None
) -> list[SearchHit]:
    if not q:
        return []
    wanted = set(types or _ALL_TYPES)
    if fts_ready(session):
        match = sanitize_fts_query(q)
        if match:
            try:
                return _fts_search(session, match, limit=limit, wanted=wanted)
            except OperationalError as exc:
                # Broken/missing index or a query shape we failed to sanitize —
                # never 500 on search syntax; fall back to the LIKE scan.
                logger.warning("fts_query_failed_falling_back_to_like", exc=str(exc))
                fts_invalidate(session)
    return _like_search(session, q, limit=limit, wanted=wanted)


def sanitize_fts_query(q: str) -> str | None:
    """Turn a free-text query into a safe FTS5 MATCH expression.

    Every whitespace-separated token is reduced to word characters
    (plus ``-._:`` so CVE IDs and versions survive) and wrapped in double
    quotes, making operators and special characters literal. Tokens are
    AND-combined — closest to the old substring semantics. Returns None when
    nothing searchable remains (caller falls back to LIKE).
    """
    terms: list[str] = []
    for tok in q.split():
        cleaned = "".join(ch for ch in tok if ch.isalnum() or ch in "-._:")
        if cleaned:
            terms.append('"' + cleaned.replace('"', '""') + '"')
    return " AND ".join(terms) if terms else None


# ------------------------- FTS5 path -------------------------


def _fts_search(session: Session, match: str, *, limit: int, wanted: set[str]) -> list[SearchHit]:
    hits: list[SearchHit] = []
    conn = session.connection()

    if "article" in wanted:
        rows = conn.exec_driver_sql(
            "SELECT a.id, bm25(articles_fts) AS rank, a.title, a.url, "
            "CASE WHEN a.summary IS NOT NULL AND a.summary != '' "
            "THEN snippet(articles_fts, 2, '', '', '…', 32) "
            "ELSE snippet(articles_fts, 1, '', '', '…', 32) END AS snip "
            "FROM articles_fts JOIN articles a ON a.id = articles_fts.rowid "
            "WHERE articles_fts MATCH ? ORDER BY rank LIMIT ?",
            (match, limit),
        ).all()
        for rid, rank, title, url, snip in rows:
            hits.append(
                SearchHit(
                    object_type="article",
                    object_id=rid,
                    title=title or url,
                    snippet=snip or "",
                    score=-rank,
                )
            )

    if "observable" in wanted:
        rows = conn.exec_driver_sql(
            "SELECT o.id, bm25(observables_fts) AS rank, o.type, o.normalized_value, "
            "o.risk_score, o.actionability "
            "FROM observables_fts JOIN observables o ON o.id = observables_fts.rowid "
            "WHERE observables_fts MATCH ? ORDER BY rank LIMIT ?",
            (match, limit),
        ).all()
        for rid, rank, otype, value, risk, actionability in rows:
            hits.append(
                SearchHit(
                    object_type="observable",
                    object_id=rid,
                    title=f"{otype}:{value}",
                    snippet=f"risk {risk:.0f} action {actionability}",
                    score=-rank,
                )
            )

    if "entity" in wanted:
        rows = conn.exec_driver_sql(
            "SELECT e.id, bm25(entities_fts) AS rank, e.type, e.canonical_name, e.aliases "
            "FROM entities_fts JOIN entities e ON e.id = entities_fts.rowid "
            "WHERE entities_fts MATCH ? ORDER BY rank LIMIT ?",
            (match, limit),
        ).all()
        for rid, rank, etype, canonical, aliases in rows:
            hits.append(
                SearchHit(
                    object_type="entity",
                    object_id=rid,
                    title=f"{etype}:{canonical}",
                    snippet=", ".join(_alias_list(aliases)),
                    score=-rank,
                )
            )

    if "claim" in wanted:
        rows = conn.exec_driver_sql(
            "SELECT c.id, bm25(claims_fts) AS rank, c.claim_type, "
            "snippet(claims_fts, 0, '', '', '…', 40) AS snip "
            "FROM claims_fts JOIN claims c ON c.id = claims_fts.rowid "
            "WHERE claims_fts MATCH ? ORDER BY rank LIMIT ?",
            (match, limit),
        ).all()
        for rid, rank, claim_type, snip in rows:
            hits.append(
                SearchHit(
                    object_type="claim",
                    object_id=rid,
                    title=claim_type,
                    snippet=snip or "",
                    score=-rank,
                )
            )

    return hits[:limit]


def _alias_list(raw) -> list[str]:
    """aliases arrives as JSON text via driver SQL; tolerate anything."""
    if isinstance(raw, list):
        return [str(a) for a in raw]
    try:
        parsed = json.loads(raw or "[]")
        return [str(a) for a in parsed] if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


# ------------------------- LIKE fallback -------------------------


def _like_search(session: Session, q: str, *, limit: int, wanted: set[str]) -> list[SearchHit]:
    """Original leading-wildcard LIKE scan — Postgres + no-FTS5 fallback."""
    needle = f"%{q.lower()}%"
    hits: list[SearchHit] = []

    if "article" in wanted:
        rows = session.scalars(
            select(Article)
            .where(
                or_(
                    Article.title.ilike(needle),
                    Article.extracted_text.ilike(needle),
                    Article.summary.ilike(needle),
                )
            )
            .limit(limit)
        )
        for art in rows:
            hits.append(
                SearchHit(
                    object_type="article",
                    object_id=art.id,
                    title=art.title or art.url,
                    snippet=(art.summary or art.extracted_text or "")[:300],
                    score=1.0,
                )
            )

    if "observable" in wanted:
        rows = session.scalars(
            select(Observable).where(Observable.normalized_value.ilike(needle)).limit(limit)
        )
        for ob in rows:
            hits.append(
                SearchHit(
                    object_type="observable",
                    object_id=ob.id,
                    title=f"{ob.type}:{ob.normalized_value}",
                    snippet=f"risk {ob.risk_score:.0f} action {ob.actionability}",
                    score=1.0,
                )
            )

    if "entity" in wanted:
        rows = session.scalars(select(Entity).where(Entity.canonical_name.ilike(needle)).limit(limit))
        for e in rows:
            hits.append(
                SearchHit(
                    object_type="entity",
                    object_id=e.id,
                    title=f"{e.type}:{e.canonical_name}",
                    snippet=", ".join(e.aliases or []),
                    score=1.0,
                )
            )

    if "claim" in wanted:
        rows = session.scalars(
            select(Claim)
            .where(or_(Claim.claim_text.ilike(needle), Claim.evidence_text.ilike(needle)))
            .limit(limit)
        )
        for c in rows:
            hits.append(
                SearchHit(
                    object_type="claim",
                    object_id=c.id,
                    title=c.claim_type,
                    snippet=c.claim_text[:300],
                    score=1.0,
                )
            )

    return hits[:limit]
