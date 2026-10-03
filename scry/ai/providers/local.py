"""Self-contained local LLM provider — GGUF via llama-cpp-python.

No server, no cloud, no API keys: the model runs embedded in the Scry
process. The (multi-second) model load is lazy — it happens on the first
chat call, never at import or app startup. `llama_cpp` itself is imported
lazily so the base install works without the optional `ai` extra.

Default model: Qwen2.5-1.5B-Instruct Q4_K_M (~1.0 GB, ~2 GB RAM at runtime —
fits 8 GB machines). A larger alternative is Llama-3.2-3B Q4 (~2 GB);
point CTI_AI_SEARCH_MODEL_PATH at any GGUF to switch.

Idle unload: holding ~2 GB RSS forever is wasteful on small machines, so a
loaded model is released after ``CTI_AI_IDLE_UNLOAD_S`` seconds without
inference (default 900; 0 disables). A daemon reaper thread (started on
load, exits on unload) does the release; the next ask transparently
reloads (~12s, same as first load). Unload takes the inference lock, so it
can never fire mid-inference.
"""

from __future__ import annotations

import contextlib
import gc
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path

import anyio

from scry.ai.providers.base import ChatChunk, LLMProvider, ModelInfo
from scry.config import get_settings
from scry.logging import get_logger

logger = get_logger("ai.local")


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

    # Idle-unload state (process-wide, like the singleton itself).
    _last_used: float = 0.0  # monotonic timestamp of the last load/inference
    _reaper: threading.Thread | None = None
    _reaper_stop = threading.Event()
    _WAKE_S = 30.0  # max reaper sleep between idle checks

    def __init__(self, api_key: str = "", base_url: str = "", default_model: str = ""):
        super().__init__(api_key, base_url, default_model)

    @property
    def model_path(self) -> Path:
        return Path(get_settings().ai_search_model_path).expanduser()

    @property
    def model_loaded(self) -> bool:
        return self._llama is not None

    @property
    def idle_seconds(self) -> float | None:
        """Seconds since the last load/inference; None when not loaded."""
        if self._llama is None or not self._last_used:
            return None
        return max(0.0, time.monotonic() - self._last_used)

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
        cls = type(self)
        cls._last_used = time.monotonic()
        if cls._llama is not None:
            return cls._llama
        with cls._load_lock:
            if cls._llama is not None:
                return cls._llama
            try:
                from llama_cpp import Llama
            except ImportError as e:
                raise RuntimeError('llama-cpp-python is not installed. Run: pip install -e ".[ai]"') from e
            if not self.is_available():
                raise RuntimeError(f"Model file not found at {self.model_path}. Run: scry ai-setup")
            cls._llama = Llama(
                model_path=str(self.model_path),
                n_ctx=4096,
                n_threads=4,
                verbose=False,
            )
            logger.info("llm_loaded", model=self.model_path.name)
            cls._ensure_reaper()
            return cls._llama

    # ------------------------- idle unload -------------------------

    @classmethod
    def _ensure_reaper(cls) -> None:
        """Start the idle-reaper daemon (called with _load_lock held, on load)."""
        if get_settings().ai_idle_unload_s <= 0:
            return
        t = cls._reaper
        if t is not None and t.is_alive():
            return
        cls._reaper_stop.clear()
        cls._reaper = threading.Thread(target=cls._reaper_loop, name="llm-idle-reaper", daemon=True)
        cls._reaper.start()

    @classmethod
    def _reaper_loop(cls) -> None:
        """Wake periodically; unload the model once it has been idle for the TTL.

        Exits when unload is disabled, when the model is gone (unloaded by
        this loop or by shutdown), or when stopped — the next load restarts
        it, so the thread never lingers without a loaded model to watch.
        """
        while not cls._reaper_stop.is_set():
            ttl = get_settings().ai_idle_unload_s
            if ttl <= 0:
                return
            wake = min(cls._WAKE_S, max(0.2, ttl / 2))
            if cls._reaper_stop.wait(wake):
                return
            if cls._llama is None:
                return
            if time.monotonic() - cls._last_used >= ttl:
                cls._drop_llama("idle_ttl", ttl=ttl)
                return

    @classmethod
    def _drop_llama(cls, reason: str, ttl: float | None = None) -> bool:
        """Release the singleton. Never fires mid-inference (takes the
        inference lock first); with ``ttl`` set, re-checks idleness under the
        locks so an inference that ran while we waited cancels the unload."""
        with cls._inference_lock, cls._load_lock:
            llama = cls._llama
            if llama is None:
                return False
            if ttl is not None and (ttl <= 0 or time.monotonic() - cls._last_used < ttl):
                return False
            cls._llama = None
        close = getattr(llama, "close", None)
        if callable(close):
            with contextlib.suppress(Exception):  # defensive
                close()
        del llama
        gc.collect()  # llama.cpp frees native memory via __del__ — push it along
        logger.info("llm_unloaded", reason=reason)
        return True

    @classmethod
    def unload(cls, reason: str = "manual") -> bool:
        """Stop the reaper and release the model now (shutdown, tests)."""
        cls._reaper_stop.set()
        return cls._drop_llama(reason)

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
            # Serialize inference: the shared Llama context is not safe for
            # concurrent use (see the class-level note on _inference_lock).
            # The lock wraps _get_llama too: the idle reaper unloads only
            # while holding this lock, so the instance reference can never
            # be dropped between fetching it and running the completion.
            with self._inference_lock:
                llama = self._get_llama()
                out = llama.create_chat_completion(messages=full_messages, max_tokens=max_tokens)
                type(self)._last_used = time.monotonic()
            return out["choices"][0]["message"]["content"] or ""

        try:
            text = await anyio.to_thread.run_sync(_run)
        except Exception as e:
            yield ChatChunk(error=str(e), done=True)
            return
        yield ChatChunk(text=text.strip(), done=True)
