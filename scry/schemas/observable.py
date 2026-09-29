from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ObservableIn(BaseModel):
    type: str
    value: str
    normalized_value: str
    defanged_value: str | None = None
    extraction_confidence: int = 60
    maliciousness_confidence: int = 50


class ObservableOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    type: str
    value: str
    normalized_value: str
    defanged_value: str | None
    validation_status: str
    extraction_confidence: int
    maliciousness_confidence: int
    false_positive_risk: float
    risk_score: float
    actionability: str
    status: str
    ttl_days: int
    first_seen: datetime | None
    last_seen: datetime | None
    first_reported: datetime | None
    last_reported: datetime | None
    expiration_date: datetime | None
    enrichment: dict = {}
    tags: list[str] = []
    scoring_model_version: str = "0"


class ObservableSearch(BaseModel):
    q: str | None = None
    type: str | None = None
    min_risk: float | None = None
    max_risk: float | None = None
    tags: list[str] = []
    status: str | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = 0
