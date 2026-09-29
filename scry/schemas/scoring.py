from __future__ import annotations

from pydantic import BaseModel, Field


class ConfidenceBreakdown(BaseModel):
    source_confidence: int = Field(ge=0, le=100)
    extraction_confidence: int = Field(ge=0, le=100)
    relationship_confidence: int = Field(ge=0, le=100)
    enrichment_confidence: int = Field(ge=0, le=100)
    maliciousness_confidence: int = Field(ge=0, le=100)
    attribution_confidence: int = Field(ge=0, le=100)
    overall_confidence: int = Field(ge=0, le=100)
    rationale: list[str] = []


class RiskScore(BaseModel):
    score: float = Field(ge=0, le=100)
    actionability: str
    contributors: list[tuple[str, float]] = []
    benign_context_flags: list[str] = []
    model_version: str = "0"
