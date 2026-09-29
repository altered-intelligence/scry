from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ArticleIn(BaseModel):
    source_id: int | None = None
    title: str = ""
    url: str
    canonical_url: str | None = None
    author: str | None = None
    published_at: datetime | None = None
    language: str | None = None
    extracted_text: str = ""
    summary: str | None = None
    tags: list[str] = []


class ArticleOut(ArticleIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source_confidence: int
    pir_ids: list[str] = []
    ingested_at: datetime | None = None
    content_hash: str | None = None


class ArticleSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    url: str
    published_at: datetime | None
    tags: list[str] = []
    source_id: int
