"""Threat feed item model — stores structured intel from external threat feeds."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class ThreatFeedItem(Base, IdMixin, TimestampMixin):
    __tablename__ = "threat_feed_items"

    # Source UUID from the feed (used for deduplication)
    uuid: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)

    # Core fields
    title: Mapped[str] = mapped_column(String(2048), default="")
    date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    priority: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Victim attributes
    victim_country: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    victim_industry: Mapped[str | None] = mapped_column(String(256), nullable=True)
    victim_organization: Mapped[str | None] = mapped_column(String(512), nullable=True)
    victim_site: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Threat actor / source
    threat_actors: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    network: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    published_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    forum_section: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Screenshots stored as JSON list of URLs
    screenshots: Mapped[list] = mapped_column(JSON, default=list)

    # Computed / enriched
    tags: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_tfi_category_date", "category", "date"),
        Index("ix_tfi_network", "network"),
        Index("ix_tfi_country", "victim_country"),
    )
