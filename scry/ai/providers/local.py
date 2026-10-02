"""Self-contained local LLM provider — GGUF via llama-cpp-python.

No server, no cloud, no API keys: the model runs embedded in the Scry
process. The (multi-second) model load is lazy — it happens on the first
chat call, never at import or app startup. `llama_cpp` itself is imported
lazily so the base install works without the optional `ai` extra.

Default model: Qwen2.5-1.5B-Instruct Q4_K_M (~1.0 GB, ~2 GB RAM at runtime —
fits 8 GB machines). A larger alternative is Llama-3.2-3B Q4 (~2 GB);
point CTI_AI_SEARCH_MODEL_PATH at any GGUF to switch.
"""

from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from pathlib import Path

import anyio

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo
from scry.config import get_settings


class LocalLlamaProvider(LLMProvider):
    name = "local"
    display_name = "Local (llama.cpp, embedded)"

    # Process-wide singleton — the model takes ~12s to load, so load once.
    _llama = None
    _load_lock = threading.Lock()
    # llama.cpp contexts are NOT thread-safe: concurrent create_chat_completion
    # calls on one Llama instance can corrupt state or crash the process.
    # Inference is therefore serialized through this lock — concurrent asks
    # queue up rather than run in parallel. Note: the endpoint-level timeout
    # (asyncio.wait_for) abandons the awaiting coroutine but cannot kill the
    # worker thread mid-inference; with the lock, subsequent asks block until
    # the runaway call finishes instead of piling onto a live context.
    _inference_lock = threading.Lock()

    def __init__(self, api_key: str = "", base_url: str = "", default_model: str = ""):
        super().__init__(api_key, base_url, default_model)

    @property
    def model_path(self) -> Path:
        return Path(get_settings().ai_search_model_path).expanduser()

    @property
    def model_loaded(self) -> bool:
        return self._llama is not None

    def is_available(self) -> bool:
        """True when the GGUF file exists on disk (no inference performed)."""
        return self.model_path.is_file()

    def list_models(self) -> list[ModelInfo]:
        if not self.is_available():
            return []
        return [
            ModelInfo(
                "local",
                self.model_path.name,
                f"Local GGUF: {self.model_path.name}",
                4096,
            )
        ]

    def _get_llama(self):
        """Lazy-load the singleton Llama instance (thread-safe, ~12s first time)."""
        if self._llama is not None:
            return self._llama
        with self._load_lock:
            if self._llama is not None:
                return self._llama
            try:
                from llama_cpp import Llama
            except ImportError as e:
                raise RuntimeError('llama-cpp-python is not installed. Run: pip install -e ".[ai]"') from e
            if not self.is_available():
                raise RuntimeError(f"Model file not found at {self.model_path}. Run: scry ai-setup")
            self._llama = Llama(
                model_path=str(self.model_path),
                n_ctx=4096,
                n_threads=4,
                verbose=False,
            )
            return self._llama

    async def chat_stream(
        self,
        messages: list[dict],
        model: str = "",
        system: str = "",
        max_tokens: int = 512,
    ) -> AsyncIterator[ChatChunk]:
        """Non-streaming under the hood; yields the full answer as one chunk.

        Runs inference in a worker thread so the caller's event loop stays
        responsive. The GGUF ships its own chat template (ChatML for Qwen),
        which llama-cpp-python applies automatically.
        """
        full_messages: list[dict] = []
        if system:
            full_messages.append({"role": "system", "content": system})
        full_messages.extend(messages)

        def _run() -> str:
            llama = self._get_llama()
            # Serialize inference: the shared Llama context is not safe for
            # concurrent use (see the class-level note on _inference_lock).
            with self._inference_lock:
                out = llama.create_chat_completion(messages=full_messages, max_tokens=max_tokens)
            return out["choices"][0]["message"]["content"] or ""

        try:
            text = await anyio.to_thread.run_sync(_run)
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
            return
        yield ChatChunk(text=text.strip(), done=True)
