from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SourceIn(BaseModel):
    name: str
    type: str
    url: str = ""
    feed: str | None = None
    enabled: bool = False
    priority: str = "medium"
    baseline_confidence: int = 60
    collection_policy: str = "safe_public_web"
    safety_mode: str | None = None
    independent: bool = False
    rate_limit_per_minute: int = 10
    tags: list[str] = []
    notes: str | None = None


class SourceOut(SourceIn):
    model_config = ConfigDict(from_attributes=True)
    id: int


class SourcePatch(BaseModel):
    """Explicit allowlist for PATCH /sources/{id} — unknown fields (including
    ``id``) are ignored instead of mass-assigned onto the ORM row."""

    name: str | None = None
    type: str | None = None
    url: str | None = None
    feed: str | None = None
    enabled: bool | None = None
    priority: str | None = None
    baseline_confidence: int | None = None
    collection_policy: str | None = None
    safety_mode: str | None = None
    independent: bool | None = None
    rate_limit_per_minute: int | None = None
    tags: list[str] | None = None
    notes: str | None = None


class SourceFetchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source_id: int
    fetched_at: datetime
    status_code: int | None
    url: str
    content_hash: str | None
    bytes_downloaded: int
    duration_ms: int
    error: str | None
