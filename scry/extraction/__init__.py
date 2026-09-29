"""Extraction pipeline orchestrator.

`Extractor.process(article)` runs all deterministic extractors + classifier
fan-out, then asks the configured LLM extractor for an enrichment pass (no-op
in the default stub configuration). All results are validated through
Pydantic schemas before any persistence happens.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scry.extraction.claim_extractor import ClaimExtractor
from scry.extraction.classifiers import classify_all
from scry.extraction.entity_extractor import EntityExtractor
from scry.extraction.ioc_extractor import IOCExtractor
from scry.extraction.llm import get_llm_extractor
from scry.extraction.relationship_extractor import RelationshipExtractor
from scry.schemas.extraction import ExtractionResult

EXTRACTOR_VERSION = "0.1"


@dataclass
class Extractor:
    ioc: IOCExtractor = field(default_factory=IOCExtractor)
    entity: EntityExtractor = field(default_factory=EntityExtractor)
    claim: ClaimExtractor = field(default_factory=ClaimExtractor)
    relationship: RelationshipExtractor = field(default_factory=RelationshipExtractor)

    def process(
        self, *, article_text: str, article_title: str = "", article_id: int | None = None
    ) -> ExtractionResult:
        text = article_text or ""
        iocs = self.ioc.extract(text)
        entities = self.entity.extract(text)
        claims = self.claim.extract(text)
        relationships = self.relationship.extract(text, iocs=iocs, entities=entities)
        topic_tags = classify_all(text)

        llm = get_llm_extractor()
        llm_result = llm.extract(article_text=text, article_title=article_title)

        cves = sorted({i.normalized_value for i in iocs if i.type == "cve"})
        attack = sorted({i.normalized_value for i in iocs if i.type == "attack_technique"})

        return ExtractionResult(
            article_id=article_id,
            iocs=iocs,
            entities=entities,
            claims=claims,
            relationships=relationships,
            tags=[t.tag for t in topic_tags],
            cves=cves,
            attack_techniques=attack,
            summary=llm_result.summary,
            extractor_version=EXTRACTOR_VERSION,
        )


__all__ = ["EXTRACTOR_VERSION", "Extractor"]
