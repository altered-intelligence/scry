"""Retry behavior tests for SafeFetcher (429/503 backoff, Retry-After)."""

from __future__ import annotations

import httpx
import pytest
import respx

import scry.ingestion.fetcher as fetcher_mod
from scry.ingestion.fetcher import (
    _MAX_ATTEMPTS,
    _RETRY_AFTER_CAP,
    SafeFetcher,
    _RetryableStatus,
)
from scry.ingestion.policy import PolicyDecision
from scry.ingestion.ssrf import SsrfDecision

_URL = "https://feeds.example.com/feed.xml"
_POLICY = PolicyDecision(
    allowed=True,
    fetch_mode="text",
    allow_javascript=False,
    allow_file_download=False,
    allow_binary_download=False,
    respect_robots_txt=False,
    max_depth=1,
    requires_analyst_approval=False,
    safety_mode=None,
)


@pytest.fixture(autouse=True)
def _no_ssrf_dns(monkeypatch):
    # Skip the DNS-resolving SSRF guard in tests (respx mocks the HTTP layer).
    monkeypatch.setattr(fetcher_mod, "evaluate_url", lambda _url: SsrfDecision(allowed=True))


@pytest.fixture
def _fast_backoff(monkeypatch):
    # Skip real 2s/4s/8s sleeps; retry logic still runs.
    monkeypatch.setattr(fetcher_mod, "_retry_wait", lambda _state: 0.01)


class _FakeOutcome:
    def __init__(self, exc):
        self._exc = exc

    def exception(self):
        return self._exc


class _FakeRetryState:
    def __init__(self, exc, attempt=1):
        self._outcome = _FakeOutcome(exc)
        self.attempt_number = attempt

    @property
    def outcome(self):
        return self._outcome


class TestRetryWait:
    """Unit tests for the real backoff function (unpatched)."""

    def _resp(self, retry_after: str | None) -> httpx.Response:
        headers = {"Retry-After": retry_after} if retry_after else {}
        return httpx.Response(429, headers=headers)

    def test_honors_retry_after(self):
        exc = _RetryableStatus(self._resp("5"))
        assert fetcher_mod._retry_wait(_FakeRetryState(exc)) == 5.0

    def test_retry_after_capped(self):
        exc = _RetryableStatus(self._resp("120"))
        assert fetcher_mod._retry_wait(_FakeRetryState(exc)) == _RETRY_AFTER_CAP

    def test_exponential_backoff_without_header(self):
        exc = _RetryableStatus(self._resp(None))
        assert fetcher_mod._retry_wait(_FakeRetryState(exc, attempt=1)) == 2.0
        assert fetcher_mod._retry_wait(_FakeRetryState(exc, attempt=2)) == 4.0
        assert fetcher_mod._retry_wait(_FakeRetryState(exc, attempt=3)) == 8.0

    def test_non_numeric_retry_after_falls_back(self):
        exc = _RetryableStatus(self._resp("Wed, 21 Oct 2099 07:28:00 GMT"))
        assert fetcher_mod._retry_wait(_FakeRetryState(exc, attempt=1)) == 2.0


@respx.mock
async def test_fetch_retries_429_then_succeeds(_fast_backoff):
    route = respx.get(_URL)
    route.side_effect = [
        httpx.Response(429),
        httpx.Response(200, text="<rss>ok</rss>", headers={"content-type": "application/rss+xml"}),
    ]
    async with SafeFetcher() as f:
        result = await f.fetch(_URL, policy=_POLICY)
    assert result.status_code == 200
    assert result.error is None
    assert "ok" in result.text
    assert route.call_count == 2


@respx.mock
async def test_fetch_persistent_429_gives_up_after_max_attempts(_fast_backoff):
    route = respx.get(_URL)
    route.mock(return_value=httpx.Response(429))
    async with SafeFetcher() as f:
        result = await f.fetch(_URL, policy=_POLICY)
    assert result.status_code == 429
    assert f"after {_MAX_ATTEMPTS} attempts" in result.error
    assert route.call_count == _MAX_ATTEMPTS


@respx.mock
async def test_get_with_retry_raises_after_max_attempts(_fast_backoff):
    respx.get(_URL).mock(return_value=httpx.Response(503))
    async with SafeFetcher() as f:
        with pytest.raises(_RetryableStatus):
            await f._get_with_retry(_URL)


@respx.mock
async def test_fetch_does_not_retry_other_4xx(_fast_backoff):
    route = respx.get(_URL)
    route.mock(return_value=httpx.Response(403, text="forbidden", headers={"content-type": "text/plain"}))
    async with SafeFetcher() as f:
        result = await f.fetch(_URL, policy=_POLICY)
    assert result.status_code == 403
    assert route.call_count == 1
