"""Workflow / runtime models: review queue, conflicts, alerts, clusters, audit, jobs."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class AnalystReview(Base, IdMixin, TimestampMixin):
    __tablename__ = "analyst_reviews"

    item_type: Mapped[str] = mapped_column(String(64), index=True)
    item_id: Mapped[int] = mapped_column(Integer, index=True)
    reason: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    article_id: Mapped[int | None] = mapped_column(
        ForeignKey("articles.id", ondelete="SET NULL"), nullable=True
    )
    evidence_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[str] = mapped_column(String(64), default="human_review")
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    disposition: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analyst: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    comments: Mapped[str | None] = mapped_column(Text, nullable=True)
    correction: Mapped[dict] = mapped_column(JSON, default=dict)


class Conflict(Base, IdMixin, TimestampMixin):
    __tablename__ = "conflicts"

    claim_a_id: Mapped[int] = mapped_column(ForeignKey("claims.id", ondelete="CASCADE"), index=True)
    claim_b_id: Mapped[int] = mapped_column(ForeignKey("claims.id", ondelete="CASCADE"), index=True)
    conflict_type: Mapped[str] = mapped_column(String(64))
    recommended_review_reason: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="open")


class Alert(Base, IdMixin, TimestampMixin):
    __tablename__ = "alerts"

    trigger: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str] = mapped_column(Text, default="")
    why_it_matters: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    related: Mapped[dict] = mapped_column(JSON, default=dict)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False)
    dedup_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)


class Cluster(Base, IdMixin, TimestampMixin):
    __tablename__ = "clusters"

    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kind: Mapped[str] = mapped_column(String(64))  # campaign_candidate, infra_cluster, etc.
    method: Mapped[str] = mapped_column(String(64), default="shared_iocs")
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    members: Mapped[dict] = mapped_column(JSON, default=dict)  # type -> [ids]
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditLog(Base, IdMixin, TimestampMixin):
    __tablename__ = "audit_logs"

    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Job(Base, IdMixin, TimestampMixin):
    __tablename__ = "jobs"

    kind: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
