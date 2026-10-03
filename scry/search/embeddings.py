"""Persisted article embeddings (v0.12.0).

Before this module, ``semantic_search`` re-embedded the ENTIRE corpus on
every query — loading every article row (bodies included) and MD5-hashing
its tokens in pure Python per request: O(N·text) time and RAM per search.

Now embeddings are computed once, at write time, and stored in the
``article_embeddings`` table:

- ``vector`` — the 384-dim hash embedding packed as little-endian float32
  (``array('f')``, 1536 bytes/row). float32 halves storage; scores are
  upcast to float64 for ranking, which is stable for ordering.
- ``dim`` — vector width guard (rows of a foreign width are skipped at
  query time; a ``VECTOR_DIM`` change also shifts every ``content_hash``,
  so the next backfill re-embeds everything automatically).
- ``content_hash`` — MD5 over ``f"{VECTOR_DIM}:{embedded text}"``; the
  embedded text is exactly what the legacy path used
  (``" ".join(filter(None, [title, summary, extracted_text]))``).

Sync points: feed ingestion, full-content fetch, OTX pulse pulls, and
pipeline (re)processing — the same hooks that maintain the FTS5 index.
Recompute is unconditional-but-hashed: the hook runs on every touch and
re-embeds only when the content hash changed (reprocess without a text
change is a no-op). Existing databases are backfilled by an idempotent,
batched migration (``scry.migrations._apply_embeddings``).

The deterministic hash-embedding algorithm itself (MD5-projected
bag-of-tokens, L2-normalized) lives here unchanged so stored vectors and
query vectors are always computed by the same code.
"""

from __future__ import annotations

import hashlib
import math
import re
from array import array
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from scry.logging import get_logger
from scry.models import Article, ArticleEmbedding

logger = get_logger("search.embeddings")

VECTOR_DIM = 384
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]+")

_BATCH = 500


def _tokens(text: str) -> Iterable[str]:
    for t in _TOKEN_RE.findall((text or "").lower()):
        if len(t) >= 2:
            yield t


def embed(text: str) -> list[float]:
    """Deterministic 384-dim hash embedding (L2-normalized)."""
    vec = [0.0] * VECTOR_DIM
    for tok in _tokens(text):
        h = hashlib.md5(tok.encode("utf-8")).digest()
        idx = int.from_bytes(h[:4], "big") % VECTOR_DIM
        sign = -1.0 if (h[4] & 1) else 1.0
        vec[idx] += sign
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def article_text(title: str | None, summary: str | None, extracted_text: str | None) -> str:
    """The exact text the legacy query path embedded."""
    return " ".join(filter(None, [title, summary, extracted_text]))


def content_hash(text: str) -> str:
    """MD5 over dim-tagged text — a VECTOR_DIM change invalidates all rows."""
    return hashlib.md5(f"{VECTOR_DIM}:{text}".encode()).hexdigest()


def pack(vec: list[float]) -> bytes:
    return array("f", vec).tobytes()


def unpack(blob: bytes) -> list[float]:
    a = array("f")
    a.frombytes(blob)
    return list(a)


def _embed_rows(rows: list[tuple]) -> list[tuple[int, bytes, str]]:
    """(id, title, summary, text) rows → (id, packed vector, content hash)."""
    out = []
    for rid, title, summary, text in rows:
        body = article_text(title, summary, text)
        out.append((rid, pack(embed(body)), content_hash(body)))
    return out


def sync_article_embeddings(session: Session, article_ids: list[int]) -> int:
    """Upsert embedding rows for the given articles (changed texts only).

    Best-effort, never raises, does NOT commit — rides the caller's
    transaction exactly like ``fts.index_rows``. Returns rows re-embedded.
    """
    if not article_ids:
        return 0
    try:
        existing = {
            row.article_id: row.content_hash
            for row in session.scalars(
                select(ArticleEmbedding).where(ArticleEmbedding.article_id.in_(article_ids))
            )
        }
        updated = 0
        for art in session.scalars(select(Article).where(Article.id.in_(article_ids))):
            body = article_text(art.title, art.summary, art.extracted_text)
            chash = content_hash(body)
            if existing.get(art.id) == chash:
                continue
            row = session.get(ArticleEmbedding, art.id)
            if row is None:
                row = ArticleEmbedding(article_id=art.id)
                session.add(row)
            row.vector = pack(embed(body))
            row.dim = VECTOR_DIM
            row.content_hash = chash
            row.updated_at = datetime.now(UTC)
            updated += 1
        return updated
    except Exception as exc:  # pragma: no cover - defensive: never break writes
        logger.warning("embedding_sync_failed", exc=str(exc))
        return 0


def backfill_embeddings(conn: Connection) -> int:
    """Idempotent batched backfill (migration path, SQLite). Returns rows embedded.

    SQLite-gated: Postgres keeps the legacy live-embed behavior (the write
    hooks still populate the table via ORM; pgvector is the real PG answer).
    """
    from sqlalchemy import inspect as sa_inspect

    if conn.dialect.name != "sqlite" or not sa_inspect(conn).has_table("article_embeddings"):
        return 0
    embedded = 0
    last_id = 0
    while True:
        rows = conn.exec_driver_sql(
            "SELECT id, title, summary, extracted_text FROM articles " "WHERE id > ? ORDER BY id LIMIT ?",
            (last_id, _BATCH),
        ).all()
        if not rows:
            break
        last_id = rows[-1][0]
        ids = [r[0] for r in rows]
        ph = ", ".join("?" for _ in ids)
        stored = dict(
            conn.exec_driver_sql(
                f"SELECT article_id, content_hash FROM article_embeddings WHERE article_id IN ({ph})",
                tuple(ids),
            ).all()
        )
        changed = [r for r in rows if stored.get(r[0]) != content_hash(article_text(r[1], r[2], r[3]))]
        if changed:
            now = datetime.now(UTC).isoformat()
            conn.exec_driver_sql(
                "INSERT OR REPLACE INTO article_embeddings "
                "(article_id, vector, dim, content_hash, updated_at) VALUES (?, ?, ?, ?, ?)",
                [(rid, blob, VECTOR_DIM, chash, now) for rid, blob, chash in _embed_rows(changed)],
            )
            embedded += len(changed)
    if embedded:
        logger.info("embeddings_backfilled", rows=embedded)
    return embedded
