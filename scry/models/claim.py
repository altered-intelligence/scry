"""Claim model — claims are first-class CTI objects."""

from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class Claim(Base, IdMixin, TimestampMixin):
    __tablename__ = "claims"

    claim_text: Mapped[str] = mapped_column(Text)
    claim_type: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    evidence_text: Mapped[str] = mapped_column(Text, default="")
    article_id: Mapped[int] = mapped_column(ForeignKey("articles.id", ondelete="CASCADE"), index=True)
    explicit_or_inferred: Mapped[str] = mapped_column(String(16), default="explicit")
    extraction_method: Mapped[str] = mapped_column(String(64), default="regex")
    review_status: Mapped[str] = mapped_column(String(32), default="unreviewed")
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    extractor_version: Mapped[str] = mapped_column(String(32), default="0")
