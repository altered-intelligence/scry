"""System-wide key/value settings stored in the DB (v0.5.0 step 2).

Currently used for the admin-configured SMTP server (keys ``smtp.*``);
later steps may add more. Values are plain strings; secrets (the SMTP
password) are stored Fernet-encrypted via ``scry.crypto.encrypt``.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class SystemSetting(Base, IdMixin, TimestampMixin):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
