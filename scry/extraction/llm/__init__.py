"""LLM interface (deferred — pluggable). Default is the stub adapter."""

from scry.extraction.llm.interface import LLMExtractor, LLMResponse  # noqa: F401
from scry.extraction.llm.stub import StubLLMExtractor


def get_llm_extractor() -> LLMExtractor:
    from scry.config import get_settings

    provider = get_settings().llm_provider
    if provider == "anthropic":
        try:
            from scry.extraction.llm.anthropic_adapter import AnthropicLLMExtractor

            return AnthropicLLMExtractor()
        except Exception:
            return StubLLMExtractor()
    return StubLLMExtractor()
