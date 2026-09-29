"""Observable + mention models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from scry.models.base import Base, IdMixin, TimestampMixin


class Observable(Base, IdMixin, TimestampMixin):
    __tablename__ = "observables"
    __table_args__ = (UniqueConstraint("type", "normalized_value", name="uq_observable_type_value"),)

    type: Mapped[str] = mapped_column(String(64), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    normalized_value: Mapped[str] = mapped_column(String(2048), index=True)
    defanged_value: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    validation_status: Mapped[str] = mapped_column(String(32), default="valid")
    extraction_confidence: Mapped[int] = mapped_column(Integer, default=60)
    maliciousness_confidence: Mapped[int] = mapped_column(Integer, default=50)
    false_positive_risk: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    actionability: Mapped[str] = mapped_column(String(32), default="monitor")
    status: Mapped[str] = mapped_column(String(32), default="active")
    ttl_days: Mapped[int] = mapped_column(Integer, default=30)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_reported: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_reported: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    scoring_model_version: Mapped[str] = mapped_column(String(32), default="0")

    mentions: Mapped[list[ObservableMention]] = relationship(
        back_populates="observable", cascade="all, delete-orphan"
    )


class ObservableMention(Base, IdMixin, TimestampMixin):
    __tablename__ = "observable_mentions"

    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"), index=True)
    article_id: Mapped[int] = mapped_column(ForeignKey("articles.id", ondelete="CASCADE"), index=True)
    evidence_text: Mapped[str] = mapped_column(Text, default="")
    context_window: Mapped[str] = mapped_column(Text, default="")
    extraction_method: Mapped[str] = mapped_column(String(64), default="regex")
    extraction_confidence: Mapped[int] = mapped_column(Integer, default=60)

    observable: Mapped[Observable] = relationship(back_populates="mentions")
