"""Idle-unload tests for the local LLM provider — fake llama_cpp, no real model."""

from __future__ import annotations

import sys
import threading
import time
import types
from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

from scry import config as _config
from scry.ai.providers.local import LocalLlamaProvider
from scry.main import app


class FakeLlama:
    instances: ClassVar[list[FakeLlama]] = []

    def __init__(self, model_path, n_ctx, n_threads, verbose):
        self.model_path = model_path
        self.closed = False
        self.completions = 0
        FakeLlama.instances.append(self)

    def create_chat_completion(self, messages, max_tokens=512):
        self.completions += 1
        return {"choices": [{"message": {"content": "fake answer"}}]}

    def close(self):
        self.closed = True


@pytest.fixture
def fake_llama_module(monkeypatch):
    mod = types.ModuleType("llama_cpp")
    mod.Llama = FakeLlama
    monkeypatch.setitem(sys.modules, "llama_cpp", mod)
    FakeLlama.instances.clear()
    return mod


@pytest.fixture
def model_file(tmp_path: Path) -> Path:
    p = tmp_path / "model.gguf"
    p.write_bytes(b"fake-gguf")
    return p


@pytest.fixture
def env(monkeypatch, model_file, fake_llama_module):
    """Fake model on disk + fresh settings cache; returns the monkeypatch so
    tests can set CTI_AI_IDLE_UNLOAD_S per-case (remember to cache_clear)."""

    monkeypatch.setenv("CTI_AI_SEARCH_MODEL_PATH", str(model_file))
    _config.get_settings.cache_clear()
    yield monkeypatch
    _config.get_settings.cache_clear()


@pytest.fixture(autouse=True)
def clean_singleton():
    """Reset the process-wide singleton and reaper around every test."""
    LocalLlamaProvider.unload(reason="test_setup")
    LocalLlamaProvider._last_used = 0.0
    yield
    LocalLlamaProvider.unload(reason="test_teardown")
    LocalLlamaProvider._last_used = 0.0
    t = LocalLlamaProvider._reaper
    if t is not None:
        t.join(timeout=5)


def _set_ttl(env, seconds: int) -> None:
    env.setenv("CTI_AI_IDLE_UNLOAD_S", str(seconds))
    _config.get_settings.cache_clear()


class TestLoadAndUnload:
    def test_load_touches_last_used(self, env):
        _set_ttl(env, 900)
        p = LocalLlamaProvider()
        assert p.model_loaded is False
        p._get_llama()
        assert p.model_loaded is True
        assert p.idle_seconds is not None and p.idle_seconds < 5

    def test_idle_unload_drops_instance(self, env):
        _set_ttl(env, 5)
        p = LocalLlamaProvider()
        p._get_llama()
        fake = FakeLlama.instances[0]
        LocalLlamaProvider._last_used = time.monotonic() - 10  # simulate idle
        assert LocalLlamaProvider._drop_llama("idle_ttl", ttl=5) is True
        assert p.model_loaded is False
        assert p.idle_seconds is None
        assert fake.closed is True

    def test_unload_skipped_when_recently_used(self, env):
        _set_ttl(env, 5)
        p = LocalLlamaProvider()
        p._get_llama()
        # Fresh timestamp (as if an inference just finished while the reaper
        # was waiting for the locks) cancels the unload.
        LocalLlamaProvider._last_used = time.monotonic()
        assert LocalLlamaProvider._drop_llama("idle_ttl", ttl=5) is False
        assert p.model_loaded is True

    def test_no_unload_mid_inference(self, env):
        _set_ttl(env, 1)
        p = LocalLlamaProvider()
        p._get_llama()
        LocalLlamaProvider._last_used = time.monotonic() - 10
        # Hold the inference lock: this is a running inference.
        LocalLlamaProvider._inference_lock.acquire()
        try:
            t = threading.Thread(target=LocalLlamaProvider.unload, daemon=True)
            t.start()
            time.sleep(0.3)
            assert p.model_loaded is True  # blocked — must not unload mid-inference
        finally:
            LocalLlamaProvider._inference_lock.release()
        t.join(timeout=5)
        assert p.model_loaded is False

    def test_ttl_zero_disables(self, env):
        _set_ttl(env, 0)
        p = LocalLlamaProvider()
        p._get_llama()
        # Reaper is never started, and an idle-TTL drop is a no-op.
        r = LocalLlamaProvider._reaper
        assert r is None or not r.is_alive()
        LocalLlamaProvider._last_used = time.monotonic() - 9999
        assert LocalLlamaProvider._drop_llama("idle_ttl", ttl=0) is False
        assert p.model_loaded is True


class TestReaperThread:
    def test_reaper_unloads_after_ttl(self, env):
        _set_ttl(env, 1)  # reaper wake = max(0.2, 0.5) = 0.5s
        p = LocalLlamaProvider()
        p._get_llama()
        assert p.model_loaded is True
        deadline = time.monotonic() + 10
        while p.model_loaded and time.monotonic() < deadline:
            time.sleep(0.1)
        assert p.model_loaded is False
        assert FakeLlama.instances[0].closed is True

    def test_reaper_exits_when_unloaded(self, env):
        _set_ttl(env, 1)
        p = LocalLlamaProvider()
        p._get_llama()
        deadline = time.monotonic() + 10
        while p.model_loaded and time.monotonic() < deadline:
            time.sleep(0.1)
        t = LocalLlamaProvider._reaper
        t.join(timeout=5)
        assert not t.is_alive()  # no lingering thread


class TestReload:
    async def test_ask_after_unload_transparently_reloads(self, env):
        _set_ttl(env, 900)
        p = LocalLlamaProvider()
        chunks = [c async for c in p.chat_stream([{"role": "user", "content": "hi"}])]
        assert chunks[-1].error is None
        assert chunks[-1].text == "fake answer"
        assert len(FakeLlama.instances) == 1

        LocalLlamaProvider.unload(reason="test")
        assert p.model_loaded is False

        chunks = [c async for c in p.chat_stream([{"role": "user", "content": "again"}])]
        assert chunks[-1].error is None
        assert chunks[-1].text == "fake answer"
        assert len(FakeLlama.instances) == 2  # a fresh instance was loaded


class TestStatus:
    def test_status_exposes_idle_fields(self, env):
        _set_ttl(env, 20)
        p = LocalLlamaProvider()
        p._get_llama()
        with TestClient(app) as client:
            data = client.get("/api/ai/status").json()
        assert data["model_loaded"] is True
        assert data["idle_unload_s"] == 20
        assert data["idle_seconds"] is not None and data["idle_seconds"] >= 0

    def test_status_idle_null_when_not_loaded(self, env):
        _set_ttl(env, 20)
        with TestClient(app) as client:
            data = client.get("/api/ai/status").json()
        assert data["model_loaded"] is False
        assert data["idle_seconds"] is None
