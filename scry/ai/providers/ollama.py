"""Ollama provider — local LLMs via HTTP at localhost:11434."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo


class OllamaProvider(LLMProvider):
    name = "ollama"
    display_name = "Ollama (local)"

    def __init__(self, api_key: str = "", base_url: str = "", default_model: str = ""):
        super().__init__(api_key, base_url or "http://localhost:11434", default_model)
        self._models_cache: list[ModelInfo] | None = None

    def list_models(self) -> list[ModelInfo]:
        if self._models_cache is not None:
            return self._models_cache
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            if r.status_code == 200:
                tags = r.json().get("models", [])
                self._models_cache = [
                    ModelInfo("ollama", t["name"], f"Ollama: {t['name']}", None) for t in tags
                ]
                return self._models_cache
        except Exception:
            pass
        self._models_cache = []
        return []

    def is_available(self) -> bool:
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=1.5)
            return r.status_code == 200
        except Exception:
            return False

    async def chat_stream(
        self,
        messages: list[dict],
        model: str,
        system: str = "",
        max_tokens: int = 4096,
    ) -> AsyncIterator[ChatChunk]:
        full_messages: list[dict] = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)

        payload = {
            "model": model,
            "messages": full_messages,
            "stream": True,
            "options": {"num_predict": max_tokens},
        }
        try:
            async with (
                httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=5.0)) as client,
                client.stream("POST", f"{self.base_url}/api/chat", json=payload) as r,
            ):
                if r.status_code != 200:
                    body = await r.aread()
                    yield ChatChunk(error=f"Ollama HTTP {r.status_code}: {body!r}", done=True)
                    return
                async for line in r.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("message") and obj["message"].get("content"):
                        yield ChatChunk(text=obj["message"]["content"])
                    if obj.get("done"):
                        yield ChatChunk(
                            done=True,
                            tokens_in=obj.get("prompt_eval_count"),
                            tokens_out=obj.get("eval_count"),
                        )
                        return
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
