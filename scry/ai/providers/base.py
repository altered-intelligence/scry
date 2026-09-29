"""Abstract LLM provider — common interface for Anthropic / OpenAI / X.AI / Google / Ollama."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass


class ProviderError(Exception):
    """Wraps any provider-side failure (auth, rate limit, network, etc.)."""


@dataclass
class ChatChunk:
    """One streamed delta from a chat completion."""

    text: str = ""
    done: bool = False
    tokens_in: int | None = None
    tokens_out: int | None = None
    error: str | None = None


@dataclass
class ModelInfo:
    provider: str
    model_id: str
    label: str
    context_window: int | None = None


class LLMProvider(ABC):
    """Common interface every provider satisfies."""

    name: str = "abstract"
    display_name: str = "Abstract Provider"

    def __init__(self, api_key: str = "", base_url: str = "", default_model: str = ""):
        self.api_key = api_key
        self.base_url = base_url
        self.default_model = default_model

    @abstractmethod
    async def chat_stream(
        self,
        messages: list[dict],
        model: str,
        system: str = "",
        max_tokens: int = 4096,
    ) -> AsyncIterator[ChatChunk]:
        """Yield ChatChunk objects as the model generates."""
        ...

    @abstractmethod
    def list_models(self) -> list[ModelInfo]:
        """Return the models this provider exposes."""
        ...

    async def test_connection(self) -> tuple[bool, str]:
        """Run a 1-token completion to verify the key works.

        Returns (ok, error_message). Default impl streams the first chunk.
        """
        try:
            model = self.default_model or (self.list_models()[0].model_id if self.list_models() else "")
            if not model:
                return False, "No model configured"
            async for chunk in self.chat_stream(
                [{"role": "user", "content": "hi"}],
                model=model,
                max_tokens=8,
            ):
                if chunk.error:
                    return False, chunk.error
                if chunk.done:
                    return True, ""
            return True, ""
        except Exception as e:
            return False, str(e)
