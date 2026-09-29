"""Source registry, fetch history, and reliability profiles."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from scry.models.base import Base, IdMixin, TimestampMixin


class Source(Base, IdMixin, TimestampMixin):
    __tablename__ = "sources"

    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    url: Mapped[str] = mapped_column(String(2048), default="")
    feed: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[str] = mapped_column(String(16), default="medium")
    baseline_confidence: Mapped[int] = mapped_column(Integer, default=60)
    collection_policy: Mapped[str] = mapped_column(String(64), default="safe_public_web")
    safety_mode: Mapped[str | None] = mapped_column(String(64), nullable=True)
    independent: Mapped[bool] = mapped_column(Boolean, default=False)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=10)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    fetches: Mapped[list[SourceFetch]] = relationship(back_populates="source", cascade="all, delete-orphan")
    reliability: Mapped[SourceReliabilityProfile | None] = relationship(
        back_populates="source", uselist=False, cascade="all, delete-orphan"
    )
    articles: Mapped[list[Article]] = relationship(back_populates="source")  # noqa: F821


class SourceFetch(Base, IdMixin, TimestampMixin):
    __tablename__ = "source_fetches"

    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    url: Mapped[str] = mapped_column(String(2048))
    content_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    bytes_downloaded: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    source: Mapped[Source] = relationship(back_populates="fetches")


class SourceReliabilityProfile(Base, IdMixin, TimestampMixin):
    __tablename__ = "source_reliability_profiles"

    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), unique=True)
    category: Mapped[str] = mapped_column(String(64), default="news")
    baseline_reliability: Mapped[int] = mapped_column(Integer, default=60)
    historical_accuracy: Mapped[float] = mapped_column(Float, default=0.75)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.1)
    vendor_bias: Mapped[float] = mapped_column(Float, default=0.0)
    sensationalism_score: Mapped[float] = mapped_column(Float, default=0.0)
    technical_depth_score: Mapped[float] = mapped_column(Float, default=0.5)
    original_research_ratio: Mapped[float] = mapped_column(Float, default=0.5)
    provides_iocs: Mapped[bool] = mapped_column(Boolean, default=False)
    provides_evidence: Mapped[bool] = mapped_column(Boolean, default=True)
    cites_primary_sources: Mapped[bool] = mapped_column(Boolean, default=True)
    is_aggregator: Mapped[bool] = mapped_column(Boolean, default=False)

    source: Mapped[Source] = relationship(back_populates="reliability")
