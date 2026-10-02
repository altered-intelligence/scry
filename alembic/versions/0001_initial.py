"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-01-01

This single revision builds the schema from the SQLAlchemy metadata so we
don't drift across 30+ tables in the MVP. Subsequent changes get their own
named migrations. After create_all, the same column/index migrations the app
applies at startup (scry.migrations.apply_migrations) run here too, so
``alembic upgrade head`` and the app's own bootstrap converge — a database
created by either path ends up with identical columns and indexes.
"""

from __future__ import annotations

from alembic import op
from scry import models  # noqa: F401  (register tables)
from scry.migrations import apply_migrations
from scry.models.base import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    apply_migrations(bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
