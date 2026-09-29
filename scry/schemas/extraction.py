"""Schemas used by extractors. Every candidate carries evidence text + confidence."""

from __future__ import annotations

from pydantic import BaseModel


class IOCCandidate(BaseModel):
    type: str
    value: str
    normalized_value: str
    defanged_value: str | None = None
    context_window: str = ""
    evidence_text: str = ""
    extraction_method: str = "regex"
    extraction_confidence: int = 60
    maliciousness_confidence: int = 50
    false_positive_risk: float = 0.0
    tags: list[str] = []


class EntityCandidate(BaseModel):
    type: str
    canonical_name: str
    surface_form: str
    aliases: list[str] = []
    evidence_text: str = ""
    extraction_method: str = "dictionary"
    extraction_confidence: int = 60


class ClaimCandidate(BaseModel):
    claim_text: str
    claim_type: str
    evidence_text: str
    confidence: int = 60
    explicit_or_inferred: str = "explicit"
    extraction_method: str = "regex"


class RelationshipCandidate(BaseModel):
    source_type: str
    source_value: str
    target_type: str
    target_value: str
    relationship_type: str
    confidence: int = 60
    evidence_text: str = ""
    explicit_or_inferred: str = "explicit"
    extraction_method: str = "regex"


class ExtractionResult(BaseModel):
    article_id: int | None = None
    iocs: list[IOCCandidate] = []
    entities: list[EntityCandidate] = []
    claims: list[ClaimCandidate] = []
    relationships: list[RelationshipCandidate] = []
    tags: list[str] = []
    cves: list[str] = []
    attack_techniques: list[str] = []
    summary: str | None = None
    extractor_version: str = "0"
