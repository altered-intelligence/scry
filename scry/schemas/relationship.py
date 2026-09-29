from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RelationshipIn(BaseModel):
    source_type: str
    source_id: int
    target_type: str
    target_id: int
    relationship_type: str
    confidence: int = 60
    evidence_text: str = ""
    article_id: int | None = None
    explicit_or_inferred: str = "explicit"
    extraction_method: str = "regex"


class RelationshipOut(RelationshipIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
