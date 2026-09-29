"""X.AI (Grok) provider — uses the OpenAI SDK pointed at X.AI's endpoint."""

from __future__ import annotations

from collections.abc import AsyncIterator

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo

_MODELS = [
    ModelInfo("xai", "grok-2-latest", "Grok 2 (latest)", 131_072),
    ModelInfo("xai", "grok-2-1212", "Grok 2 (1212 snapshot)", 131_072),
    ModelInfo("xai", "grok-2-mini", "Grok 2 mini", 131_072),
    ModelInfo("xai", "grok-beta", "Grok beta", 131_072),
]


class XAIProvider(LLMProvider):
    name = "xai"
    display_name = "X.AI (Grok)"

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
            from openai import AsyncOpenAI
        except ImportError:
            yield ChatChunk(error="openai SDK not installed", done=True)
            return

        if not self.api_key:
            yield ChatChunk(error="X.AI API key not set", done=True)
            return

        client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=self.base_url or "https://api.x.ai/v1",
        )

        full_messages: list[dict] = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)

        try:
            stream = await client.chat.completions.create(
                model=model,
                messages=full_messages,
                max_tokens=max_tokens,
                stream=True,
            )
            async for event in stream:
                if event.choices and event.choices[0].delta and event.choices[0].delta.content:
                    yield ChatChunk(text=event.choices[0].delta.content)
            yield ChatChunk(done=True)
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
