"""Semantic search with offline-safe fallback.

For an MVP that must run with zero external infra, we use a deterministic
hashing embedding (bag-of-tokens projected into a 384-dim vector). When a
real embedding model is wired up later, it slots in behind the same
`embed()` function.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Article, Claim
from scry.schemas.search import SearchHit

VECTOR_DIM = 384
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]+")


def _tokens(text: str) -> Iterable[str]:
    for t in _TOKEN_RE.findall((text or "").lower()):
        if len(t) >= 2:
            yield t


def embed(text: str) -> list[float]:
    vec = [0.0] * VECTOR_DIM
    for tok in _tokens(text):
        h = hashlib.md5(tok.encode("utf-8")).digest()
        idx = int.from_bytes(h[:4], "big") % VECTOR_DIM
        sign = -1.0 if (h[4] & 1) else 1.0
        vec[idx] += sign
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


def semantic_search(
    session: Session, q: str, *, target: str = "articles", limit: int = 20
) -> list[SearchHit]:
    if not q:
        return []
    qvec = embed(q)
    out: list[tuple[float, SearchHit]] = []
    if target == "articles":
        for art in session.scalars(select(Article)):
            text = " ".join(filter(None, [art.title, art.summary, art.extracted_text]))
            score = _cosine(qvec, embed(text))
            out.append(
                (
                    score,
                    SearchHit(
                        object_type="article",
                        object_id=art.id,
                        title=art.title or art.url,
                        snippet=(art.summary or art.extracted_text or "")[:300],
                        score=score,
                    ),
                )
            )
    elif target == "claims":
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
