"""Entity and entity mention models (actors, malware, campaigns, etc.)."""

from __future__ import annotations

from sqlalchemy import JSON, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from scry.models.base import Base, IdMixin, TimestampMixin


class Entity(Base, IdMixin, TimestampMixin):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("type", "canonical_name", name="uq_entity_type_name"),)

    type: Mapped[str] = mapped_column(String(64), index=True)
    canonical_name: Mapped[str] = mapped_column(String(255), index=True)
    aliases: Mapped[list] = mapped_column(JSON, default=list)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[int] = mapped_column(Integer, default=60)
    tags: Mapped[list] = mapped_column(JSON, default=list)

    mentions: Mapped[list[EntityMention]] = relationship(
        back_populates="entity", cascade="all, delete-orphan"
    )


class EntityMention(Base, IdMixin, TimestampMixin):
    __tablename__ = "entity_mentions"

    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    article_id: Mapped[int] = mapped_column(ForeignKey("articles.id", ondelete="CASCADE"), index=True)
    evidence_text: Mapped[str] = mapped_column(Text, default="")
    extraction_method: Mapped[str] = mapped_column(String(64), default="dictionary")
    extraction_confidence: Mapped[int] = mapped_column(Integer, default=60)

    entity: Mapped[Entity] = relationship(back_populates="mentions")
