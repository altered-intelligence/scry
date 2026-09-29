"""Telegram channel model — stores CTI-relevant Telegram channels."""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class TelegramChannel(Base, IdMixin, TimestampMixin):
    __tablename__ = "telegram_channels"

    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
