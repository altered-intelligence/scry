from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ReviewItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    item_type: str
    item_id: int
    reason: str
    confidence: int
    article_id: int | None
    evidence_text: str | None
    recommended_action: str
    status: str
    disposition: str | None
    analyst: str | None
    reviewed_at: datetime | None
    comments: str | None
    correction: dict = {}


class ReviewUpdate(BaseModel):
    status: str | None = None
    disposition: str | None = None
    analyst: str | None = None
    comments: str | None = None
    correction: dict | None = None
