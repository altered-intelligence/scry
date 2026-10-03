"""Article and content snapshot models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from scry.models.base import Base, IdMixin, TimestampMixin


class Article(Base, IdMixin, TimestampMixin):
    __tablename__ = "articles"

    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(1024), default="")
    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    canonical_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    author: Mapped[str | None] = mapped_column(String(255), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    raw_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    extracted_text: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_confidence: Mapped[int] = mapped_column(Integer, default=60)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    pir_ids: Mapped[list] = mapped_column(JSON, default=list)
    parser_version: Mapped[str] = mapped_column(String(32), default="0")
    extractor_version: Mapped[str] = mapped_column(String(32), default="0")

    source: Mapped[Source] = relationship(back_populates="articles")  # noqa: F821


class ArticleEmbedding(Base):
    """Persisted semantic-search vector for one article (v0.12.0).

    ``vector`` packs the 384-dim hash embedding as little-endian float32;
    ``content_hash`` (MD5 over dim + embedded text) drives invalidation.
    See ``scry/search/embeddings.py``.
    """

    __tablename__ = "article_embeddings"

    article_id: Mapped[int] = mapped_column(ForeignKey("articles.id", ondelete="CASCADE"), primary_key=True)
    vector: Mapped[bytes] = mapped_column(LargeBinary)
    dim: Mapped[int] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
