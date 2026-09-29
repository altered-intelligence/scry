"""Relationship model — typed links between objects with provenance."""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class Relationship(Base, IdMixin, TimestampMixin):
    __tablename__ = "relationships"

    source_type: Mapped[str] = mapped_column(String(64), index=True)
    source_id: Mapped[int] = mapped_column(Integer, index=True)
    target_type: Mapped[str] = mapped_column(String(64), index=True)
    target_id: Mapped[int] = mapped_column(Integer, index=True)
    relationship_type: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    evidence_text: Mapped[str] = mapped_column(Text, default="")
    article_id: Mapped[int | None] = mapped_column(
        ForeignKey("articles.id", ondelete="SET NULL"), nullable=True, index=True
    )
    explicit_or_inferred: Mapped[str] = mapped_column(String(16), default="explicit")
    extraction_method: Mapped[str] = mapped_column(String(64), default="regex")
    extractor_version: Mapped[str] = mapped_column(String(32), default="0")
