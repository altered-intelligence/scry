"""Abstract LLM extractor interface.

Validated, evidence-bound output — never store an LLM claim without
matching evidence text from the source article.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from pydantic import BaseModel

from scry.schemas.extraction import ExtractionResult


class LLMResponse(BaseModel):
    summary: str | None = None
    key_findings: list[str] = []


class LLMExtractor(ABC):
    name: str = "base"

    @abstractmethod
    def extract(self, *, article_text: str, article_title: str = "") -> ExtractionResult: ...
