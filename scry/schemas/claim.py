from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ClaimIn(BaseModel):
    claim_text: str
    claim_type: str
    confidence: int = 60
    evidence_text: str = ""
    article_id: int
    explicit_or_inferred: str = "explicit"
    extraction_method: str = "regex"


class ClaimOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    claim_text: str
    claim_type: str
    confidence: int = Field(ge=0, le=100)
    evidence_text: str
    article_id: int
    explicit_or_inferred: str
    extraction_method: str
    review_status: str
    needs_review: bool
