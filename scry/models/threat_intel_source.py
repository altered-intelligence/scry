"""ThreatIntelSource model — persists configuration for each external threat feed."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class ThreatIntelSource(Base, IdMixin, TimestampMixin):
    __tablename__ = "threat_intel_sources"

    # Identity
    name: Mapped[str] = mapped_column(String(256))
    slug: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(128), index=True)
    url: Mapped[str] = mapped_column(String(2048))

    # Feed metadata
    feed_format: Mapped[str] = mapped_column(String(32))  # csv | freetext | misp
    category: Mapped[str] = mapped_column(String(64), default="mixed")  # ip | domain | url | hash | mixed
    auto_tags: Mapped[list] = mapped_column(JSON, default=list)
    base_risk_score: Mapped[float] = mapped_column(Float, default=60.0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Config
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Run history
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_count: Mapped[int] = mapped_column(Integer, default=0)
    last_run_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # ok | error | partial
