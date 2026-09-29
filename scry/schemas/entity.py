from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class EntityIn(BaseModel):
    type: str
    canonical_name: str
    aliases: list[str] = []
    description: str | None = None
    attributes: dict = {}
    confidence: int = 60
    tags: list[str] = []


class EntityOut(EntityIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
