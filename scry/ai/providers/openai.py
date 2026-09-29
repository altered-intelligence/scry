"""OpenAI provider — uses the official SDK with streaming.

Base URL configuration:
- Leave blank (default): uses https://api.openai.com/v1
- Custom base URL: for OpenAI-compatible APIs (e.g., Azure OpenAI, local proxies)
  Example: https://your-resource.openai.azure.com/

Available models are regularly updated. If a model is not in the list below,
you can still use it by manually specifying the model ID when making API calls.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo

_MODELS = [
    ModelInfo("openai", "gpt-4o", "GPT-4o", 128_000),
    ModelInfo("openai", "gpt-4o-mini", "GPT-4o mini (fast/cheap)", 128_000),
    ModelInfo("openai", "gpt-4-turbo", "GPT-4 Turbo", 128_000),
    ModelInfo("openai", "o1", "o1 (reasoning)", 200_000),
    ModelInfo("openai", "o1-preview", "o1-preview (reasoning)", 128_000),
    ModelInfo("openai", "o1-mini", "o1-mini (reasoning)", 128_000),
    ModelInfo("openai", "o3-mini", "o3-mini (reasoning)", 200_000),
    ModelInfo("openai", "chatgpt-4o-latest", "ChatGPT-4o (latest)", 128_000),
]


class OpenAIProvider(LLMProvider):
    name = "openai"
    display_name = "OpenAI"

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
            yield ChatChunk(error="OpenAI API key not set", done=True)
            return

        client_kwargs: dict = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        client = AsyncOpenAI(**client_kwargs)

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
                stream_options={"include_usage": True},
            )
            tokens_in = tokens_out = None
            async for event in stream:
                if event.choices and event.choices[0].delta and event.choices[0].delta.content:
                    yield ChatChunk(text=event.choices[0].delta.content)
                if event.usage:
                    tokens_in = event.usage.prompt_tokens
                    tokens_out = event.usage.completion_tokens
            yield ChatChunk(done=True, tokens_in=tokens_in, tokens_out=tokens_out)
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
