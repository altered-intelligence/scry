"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-01-01

This single revision builds the schema from the SQLAlchemy metadata so we
don't drift across 30+ tables in the MVP. Subsequent changes get their own
named migrations.
"""

from __future__ import annotations

from alembic import op
from scry import models  # noqa: F401  (register tables)
from scry.models.base import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
