"""Full-text search.

Pragmatic LIKE-based search across articles/observables/entities/claims.
For Postgres deployments, this can be upgraded to tsvector + GIN indexes;
for SQLite / MVP, ILIKE-equivalent (`LIKE` with lower()) is good enough.
"""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from scry.models import Article, Claim, Entity, Observable
from scry.schemas.search import SearchHit


def full_text_search(
    session: Session, q: str, *, limit: int = 50, types: list[str] | None = None
) -> list[SearchHit]:
    if not q:
        return []
    needle = f"%{q.lower()}%"
    wanted = set(types or ["article", "observable", "entity", "claim"])
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
