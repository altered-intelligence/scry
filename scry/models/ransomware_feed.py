"""Ransomware feed item model — stores victim/claim data from ransomware group leak sites."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class RansomwareFeedItem(Base, IdMixin, TimestampMixin):
    __tablename__ = "ransomware_feed_items"

    # Source dedup key (post_title + group_name hash)
    post_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True, index=True)

    # Core fields
    post_title: Mapped[str] = mapped_column(String(2048), default="")
    group_name: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    discovered: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    activity: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)  # industry/sector

    # Victim attributes
    victim_website: Mapped[str | None] = mapped_column(String(512), nullable=True)
    victim_country: Mapped[str | None] = mapped_column(String(8), nullable=True, index=True)

    # Links
    post_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    claim_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)  # onion URL

    # Computed / enriched
    tags: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    ingested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_rfi_group_discovered", "group_name", "discovered"),
        Index("ix_rfi_activity", "activity"),
        Index("ix_rfi_country", "victim_country"),
    )
