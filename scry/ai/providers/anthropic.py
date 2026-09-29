"""Anthropic Claude provider — uses the official SDK with streaming."""

from __future__ import annotations

from collections.abc import AsyncIterator

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo

_MODELS = [
    ModelInfo("anthropic", "claude-opus-4-7", "Claude Opus 4.7 (most capable)", 1_000_000),
    ModelInfo("anthropic", "claude-opus-4-6", "Claude Opus 4.6", 1_000_000),
    ModelInfo("anthropic", "claude-sonnet-4-6", "Claude Sonnet 4.6 (balanced)", 1_000_000),
    ModelInfo("anthropic", "claude-haiku-4-5", "Claude Haiku 4.5 (fast/cheap)", 200_000),
]


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    display_name = "Anthropic Claude"

    def list_models(self) -> list[ModelInfo]:
        return _MODELS

    async def chat_stream(
        self,
        messages: list[dict],
        model: str,
        system: str = "",
        max_tokens: int = 4096,
    ) -> AsyncIterator[ChatChunk]:
        try:
            from anthropic import AsyncAnthropic
        except ImportError:
            yield ChatChunk(error="anthropic SDK not installed", done=True)
            return

        if not self.api_key:
            yield ChatChunk(error="Anthropic API key not set", done=True)
            return

        client = AsyncAnthropic(api_key=self.api_key)

        # Filter out system messages from the messages list (Anthropic puts them in `system=`)
        msgs = [m for m in messages if m.get("role") in ("user", "assistant")]
        kwargs: dict = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": msgs,
        }
        if system:
            kwargs["system"] = system

        try:
            async with client.messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    yield ChatChunk(text=text)
                final = await stream.get_final_message()
                yield ChatChunk(
                    done=True,
                    tokens_in=final.usage.input_tokens,
                    tokens_out=final.usage.output_tokens,
                )
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
