"""Semantic search over persisted embeddings.

Articles: only the QUERY is embedded at request time; article vectors come
from the ``article_embeddings`` table (see ``scry/search/embeddings.py``),
loaded columnar (id + blob — never article bodies) and scored in one shot
with numpy when available, identical pure-Python math otherwise. The final
top-k rows are the only articles fetched (for titles/snippets). Articles
missing a stored row (never migrated/hooked) are embedded on the fly —
bounded to those stragglers, never the whole corpus.

Claims stay on the legacy live-embed path: claim texts are tiny and few.

The deterministic hash embedding lives in ``scry/search/embeddings.py``
(re-exported here); a real embedding model would slot in behind `embed()`.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Article, ArticleEmbedding, Claim
from scry.schemas.search import SearchHit
from scry.search.embeddings import VECTOR_DIM, article_text, embed, unpack

__all__ = ["VECTOR_DIM", "embed", "semantic_search"]


def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


def _score_stored(qvec: list[float], rows: list[tuple[int, bytes]]) -> list[tuple[float, int]]:
    """Score (id, packed-vector) rows against the query vector, best first."""
    valid = [(rid, blob) for rid, blob in rows if len(blob) == 4 * VECTOR_DIM]
    if not valid:
        return []
    try:
        import numpy as np

        ids = np.fromiter((rid for rid, _ in valid), dtype=np.int64, count=len(valid))
        mat = np.frombuffer(b"".join(blob for _, blob in valid), dtype=np.float32).reshape(
            len(valid), VECTOR_DIM
        )
        # Vectors are L2-normalized at write time; dot == cosine. Upcast to
        # float64 so ordering matches the pure-Python path bit-for-bit-ish.
        scores = mat.astype(np.float64) @ np.asarray(qvec, dtype=np.float64)
        order = np.argsort(-scores)
        return [(float(scores[i]), int(ids[i])) for i in order]
    except ImportError:  # numpy lives in the `ai` extra; base installs score in Python
        scored = [(float(_cosine(qvec, unpack(blob))), rid) for rid, blob in valid]
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored


def _article_search(session: Session, qvec: list[float], limit: int) -> list[SearchHit]:
    rows = session.execute(select(ArticleEmbedding.article_id, ArticleEmbedding.vector)).all()
    scored = _score_stored(qvec, [(r[0], r[1]) for r in rows])

    have = {rid for _, rid in scored}
    missing = session.scalars(
        select(Article.id).where(Article.id.not_in(select(ArticleEmbedding.article_id)))
    ).all()
    if missing:
        for art in session.scalars(select(Article).where(Article.id.in_(missing))):
            # Straggler without a stored row — embed just this one on the fly.
            if art.id not in have:
                scored.append(
                    (
                        _cosine(qvec, embed(article_text(art.title, art.summary, art.extracted_text))),
                        art.id,
                    )
                )
    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:limit]
    if not top:
        return []

    arts = {a.id: a for a in session.scalars(select(Article).where(Article.id.in_([rid for _, rid in top])))}
    out: list[SearchHit] = []
    for score, rid in top:
        art = arts.get(rid)
        if art is None:  # embedding row outlived its article (pre-CASCADE)
            continue
        out.append(
            SearchHit(
                object_type="article",
                object_id=art.id,
                title=art.title or art.url,
                snippet=(art.summary or art.extracted_text or "")[:300],
                score=score,
            )
        )
    return out


def semantic_search(
    session: Session, q: str, *, target: str = "articles", limit: int = 20
) -> list[SearchHit]:
    if not q:
        return []
    qvec = embed(q)
    if target == "articles":
        return _article_search(session, qvec, limit)

    out: list[tuple[float, SearchHit]] = []
    for cl in session.scalars(select(Claim)):
        text = f"{cl.claim_type} {cl.claim_text} {cl.evidence_text}"
        score = _cosine(qvec, embed(text))
        out.append(
            (
                score,
                SearchHit(
                    object_type="claim",
                    object_id=cl.id,
                    title=cl.claim_type,
                    snippet=cl.claim_text[:300],
                    score=score,
                ),
            )
        )
    out.sort(key=lambda x: x[0], reverse=True)
    return [hit for _, hit in out[:limit]]
