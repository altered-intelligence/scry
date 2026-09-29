"""Audit logging helper. Writes audit entries to the DB."""

from __future__ import annotations

from sqlalchemy.orm import Session

from scry.models import AuditLog


def record(
    session: Session,
    *,
    action: str,
    actor: str = "system",
    target_type: str | None = None,
    target_id: int | None = None,
    detail: dict | None = None,
) -> None:
    session.add(
        AuditLog(
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
        )
    )
    session.commit()
