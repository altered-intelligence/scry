"""Stub LLM extractor.

Returns an empty ExtractionResult. The deterministic extractors do the
heavy lifting in MVP; this exists so the rest of the system can call into a
single, stable interface without depending on an external model.
"""

from __future__ import annotations

from scry.extraction.llm.interface import LLMExtractor
from scry.schemas.extraction import ExtractionResult


class StubLLMExtractor(LLMExtractor):
    name = "stub"

    def extract(self, *, article_text: str, article_title: str = "") -> ExtractionResult:
        return ExtractionResult(summary=None, extractor_version="stub-0")
