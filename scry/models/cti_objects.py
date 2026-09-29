"""Malware family, threat actor, campaign, attack mapping, detection."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class MalwareFamily(Base, IdMixin, TimestampMixin):
    __tablename__ = "malware_families"

    canonical_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    malware_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    target_os: Mapped[list] = mapped_column(JSON, default=list)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    delivery_methods: Mapped[list] = mapped_column(JSON, default=list)
    c2_protocol: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    first_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=60)


class ThreatActor(Base, IdMixin, TimestampMixin):
    __tablename__ = "threat_actors"

    canonical_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    suspected_origin: Mapped[str | None] = mapped_column(String(64), nullable=True)
    motivation: Mapped[list] = mapped_column(JSON, default=list)
    sophistication: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_sectors: Mapped[list] = mapped_column(JSON, default=list)
    target_geographies: Mapped[list] = mapped_column(JSON, default=list)
    known_malware: Mapped[list] = mapped_column(JSON, default=list)
    known_tools: Mapped[list] = mapped_column(JSON, default=list)
    known_ttps: Mapped[list] = mapped_column(JSON, default=list)
    attribution_confidence: Mapped[str] = mapped_column(String(16), default="possible")
    first_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Campaign(Base, IdMixin, TimestampMixin):
    __tablename__ = "campaigns"

    name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    timeframe_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    timeframe_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    target_sectors: Mapped[list] = mapped_column(JSON, default=list)
    target_geographies: Mapped[list] = mapped_column(JSON, default=list)
    initial_access: Mapped[list] = mapped_column(JSON, default=list)
    delivery_mechanism: Mapped[list] = mapped_column(JSON, default=list)
    malware_used: Mapped[list] = mapped_column(JSON, default=list)
    tools_used: Mapped[list] = mapped_column(JSON, default=list)
    objective: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=60)


class AttackMapping(Base, IdMixin, TimestampMixin):
    """ATT&CK mapping for an article, claim, malware, or campaign."""

    __tablename__ = "attack_mappings"

    parent_type: Mapped[str] = mapped_column(String(64), index=True)
    parent_id: Mapped[int] = mapped_column(Integer, index=True)
    technique_id: Mapped[str] = mapped_column(String(32), index=True)
    technique_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sub_technique_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    evidence_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    explicit_or_inferred: Mapped[str] = mapped_column(String(16), default="inferred")


class Detection(Base, IdMixin, TimestampMixin):
    __tablename__ = "detections"

    title: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(
        String(32), index=True
    )  # sigma, yara, suricata, snort, kql, spl, eql
    body: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    required_telemetry: Mapped[list] = mapped_column(JSON, default=list)
    false_positive_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    generated: Mapped[bool] = mapped_column(Boolean, default=True)
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    article_id: Mapped[int | None] = mapped_column(
        ForeignKey("articles.id", ondelete="SET NULL"), nullable=True
    )
