from __future__ import annotations

from pydantic import BaseModel, Field


class SearchQuery(BaseModel):
    q: str
    types: list[str] = []
    sources: list[int] = []
    tags: list[str] = []
    since: str | None = None
    until: str | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = 0


class SemanticQuery(BaseModel):
    q: str
    target: str = "articles"  # articles | claims | campaigns
    limit: int = Field(default=20, ge=1, le=200)


class SearchHit(BaseModel):
    object_type: str
    object_id: int
    title: str | None = None
    snippet: str = ""
    score: float
