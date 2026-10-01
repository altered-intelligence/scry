"""AI Search — ChatSession & ChatMessage models."""

from __future__ import annotations

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from scry.models.base import Base, IdMixin, TimestampMixin


class ChatSession(Base, IdMixin, TimestampMixin):
    __tablename__ = "chat_sessions"

    title: Mapped[str] = mapped_column(String(512), default="New conversation")
    # Auto-derived from first user message; user can rename
    pinned_model_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    pinned_model_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    message_count: Mapped[int] = mapped_column(Integer, default=0)
    archived: Mapped[bool] = mapped_column(default=False)
    # Owning user (v0.5.0 step 3, per-user chat privacy). NULL = legacy
    # shared session, readable by anyone who can use the AI endpoints.
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    messages: Mapped[list[ChatMessage]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="ChatMessage.id",
    )

    __table_args__ = (Index("ix_chat_sessions_archived", "archived"),)


class ChatMessage(Base, IdMixin, TimestampMixin):
    __tablename__ = "chat_messages"

    session_id: Mapped[int] = mapped_column(ForeignKey("chat_sessions.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(16))  # user | assistant | system
    content: Mapped[str] = mapped_column(Text, default="")

    # Which provider+model produced this assistant message
    model_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Sources cited / retrieved as context. JSON list of:
    #   {"type": "article|observable|cve|entity|threat_feed|ransomware_feed",
    #    "id": int, "title": str, "snippet": str, "url": str}
    sources: Mapped[list] = mapped_column(JSON, default=list)

    # Usage stats
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Error message if generation failed (still saved to keep history)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # For retry/branching — points at the assistant message being regenerated
    parent_message_id: Mapped[int | None] = mapped_column(
        ForeignKey("chat_messages.id", ondelete="SET NULL"), nullable=True
    )

    session: Mapped[ChatSession] = relationship(back_populates="messages")
