"""Review queue helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.logging import get_logger
from scry.models import AnalystReview

logger = get_logger("review")


class ReviewQueue:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list_open(self, *, limit: int = 100, offset: int = 0) -> list[AnalystReview]:
        return list(
            self.session.scalars(
                select(AnalystReview)
                .where(AnalystReview.status == "open")
                .order_by(AnalystReview.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )

    def update(
        self,
        review_id: int,
        *,
        status: str | None = None,
        disposition: str | None = None,
        analyst: str | None = None,
        comments: str | None = None,
        correction: dict | None = None,
    ) -> AnalystReview | None:
        row = self.session.get(AnalystReview, review_id)
        if row is None:
            return None
        if status is not None:
            row.status = status
        if disposition is not None:
            row.disposition = disposition
        if analyst is not None:
            row.analyst = analyst
        if comments is not None:
            row.comments = comments
        if correction is not None:
            row.correction = correction
        row.reviewed_at = datetime.now(UTC)
        self.session.commit()
        return row
