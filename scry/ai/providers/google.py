"""Google Gemini provider — uses google-generativeai."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo

_MODELS = [
    ModelInfo("google", "gemini-2.0-flash-exp", "Gemini 2.0 Flash (experimental)", 1_048_576),
    ModelInfo("google", "gemini-1.5-pro", "Gemini 1.5 Pro", 2_097_152),
    ModelInfo("google", "gemini-1.5-flash", "Gemini 1.5 Flash (fast/cheap)", 1_048_576),
    ModelInfo("google", "gemini-1.5-flash-8b", "Gemini 1.5 Flash 8B", 1_048_576),
]


class GoogleProvider(LLMProvider):
    name = "google"
    display_name = "Google Gemini"

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
            import google.generativeai as genai
        except ImportError:
            yield ChatChunk(error="google-generativeai SDK not installed", done=True)
            return

        if not self.api_key:
            yield ChatChunk(error="Google API key not set", done=True)
            return

        genai.configure(api_key=self.api_key)

        # Convert OpenAI-style messages to Gemini format
        history: list[dict] = []
        last_user_msg = ""
        for m in messages:
            role = "user" if m["role"] == "user" else "model"
            if m == messages[-1] and m["role"] == "user":
                last_user_msg = m["content"]
            else:
                history.append({"role": role, "parts": [m["content"]]})

        try:
            gen_model = genai.GenerativeModel(
                model_name=model,
                system_instruction=system if system else None,
            )
            chat = gen_model.start_chat(history=history)
            # The Gemini SDK is sync; run send_message in a thread and adapt to async
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: chat.send_message(
                    last_user_msg,
                    stream=True,
                    generation_config={"max_output_tokens": max_tokens},
                ),
            )
            # Iterate chunks (also sync iterator; use run_in_executor on next())
            iterator = iter(response)
            while True:
                try:
                    chunk = await loop.run_in_executor(None, lambda: next(iterator, None))
                except StopIteration:
                    break
                if chunk is None:
                    break
                if hasattr(chunk, "text") and chunk.text:
                    yield ChatChunk(text=chunk.text)
            yield ChatChunk(done=True)
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
