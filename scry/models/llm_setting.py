"""LLM provider settings — encrypted API keys + configuration."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class LLMSetting(Base, IdMixin, TimestampMixin):
    __tablename__ = "llm_settings"

    # Unique provider name: anthropic | openai | xai | google | ollama
    provider: Mapped[str] = mapped_column(String(32), unique=True, index=True)

    # API key encrypted at rest via scry.crypto.encrypt()
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional override URL (mainly for Ollama: http://localhost:11434)
    base_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Default model to use if user doesn't specify
    default_model: Mapped[str | None] = mapped_column(String(128), nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Last connection-test result
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_check_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_check_error: Mapped[str | None] = mapped_column(Text, nullable=True)
