"""Deduplication helpers.

Article-level: dedupe by URL + content_hash. Observable-level: enforced by
DB unique constraint on (type, normalized_value).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Article


def find_duplicate_article(session: Session, *, url: str, content_hash: str | None = None) -> Article | None:
    existing = session.scalar(select(Article).where(Article.url == url))
    if existing:
        return existing
    if content_hash:
        existing = session.scalar(select(Article).where(Article.content_hash == content_hash))
        if existing:
            return existing
    return None
