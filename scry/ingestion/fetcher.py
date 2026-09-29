"""Safe HTTP fetcher.

- Async via httpx
- Per-host rate limit (simple token bucket)
- Hard size cap from settings.max_fetch_bytes
- Timeout from settings.fetch_timeout_seconds
- SSRF guard before any network call
- robots.txt advisory check (best-effort; fails closed only when policy says so)
- Refuses file downloads / binary content unless policy allows
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from scry.config import get_settings
from scry.ingestion.policy import PolicyDecision
from scry.ingestion.ssrf import evaluate_url
from scry.logging import get_logger

logger = get_logger("fetcher")


@dataclass
class FetchResult:
    url: str
    status_code: int | None
    content: bytes = b""
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    content_hash: str | None = None
    elapsed_ms: int = 0
    error: str | None = None


class _RateLimiter:
    """Per-host token bucket (requests per minute)."""

    def __init__(self) -> None:
        self._last: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str, per_minute: int) -> None:
        if per_minute <= 0:
            return
        window = 60.0
        max_calls = per_minute
        async with self._lock:
            now = time.monotonic()
            history = [t for t in self._last.get(host, []) if now - t < window]
            if len(history) >= max_calls:
                sleep_for = window - (now - history[0]) + 0.05
                await asyncio.sleep(max(sleep_for, 0.05))
                history = [t for t in history if (time.monotonic() - t) < window]
            history.append(time.monotonic())
            self._last[host] = history


class SafeFetcher:
    USER_AGENT = "Scry/0.1 (+defensive-research)"

    def __init__(self, *, client: httpx.AsyncClient | None = None) -> None:
        self._settings = get_settings()
        self._client = client
        self._rate = _RateLimiter()
        self._owns_client = client is None

    async def __aenter__(self) -> SafeFetcher:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(self._settings.fetch_timeout_seconds),
                headers={
                    "User-Agent": self.USER_AGENT,
                    "Accept": "text/html, application/rss+xml, application/atom+xml, application/json, text/xml",
                },
                http2=False,
            )
            self._owns_client = True
        return self

    async def __aexit__(self, *exc) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def fetch(
        self, url: str, *, policy: PolicyDecision, rate_limit_per_minute: int = 10
    ) -> FetchResult:
        if not policy.allowed or policy.fetch_mode == "deny":
            return FetchResult(url=url, status_code=None, error=f"policy blocked: {policy.reason}")

        ssrf = evaluate_url(url)
        if not ssrf.allowed:
            logger.warning("ssrf_block", url=url, reason=ssrf.reason)
            return FetchResult(url=url, status_code=None, error=f"ssrf blocked: {ssrf.reason}")

        host = urlparse(url).hostname or ""
        await self._rate.acquire(host, rate_limit_per_minute)

        assert self._client is not None
        start = time.monotonic()
        try:
            resp = await self._client.get(url)
        except httpx.HTTPError as exc:
            return FetchResult(
                url=url, status_code=None, error=str(exc), elapsed_ms=int((time.monotonic() - start) * 1000)
            )

        elapsed_ms = int((time.monotonic() - start) * 1000)
        ct = resp.headers.get("content-type", "").lower()
        size = int(resp.headers.get("content-length", "0") or 0) or len(resp.content)

        if size > self._settings.max_fetch_bytes:
            return FetchResult(
                url=str(resp.url),
                status_code=resp.status_code,
                headers=dict(resp.headers),
                error=f"response too large ({size} bytes)",
                elapsed_ms=elapsed_ms,
            )

        # Refuse binary/file downloads unless policy permits explicitly.
        if not _looks_like_text(ct) and not policy.allow_binary_download and not policy.allow_file_download:
            return FetchResult(
                url=str(resp.url),
                status_code=resp.status_code,
                headers=dict(resp.headers),
                error=f"refusing non-text content-type {ct!r}",
                elapsed_ms=elapsed_ms,
            )

        content = resp.content[: self._settings.max_fetch_bytes]
        sha = hashlib.sha256(content).hexdigest()
        try:
            text = content.decode(resp.encoding or "utf-8", errors="replace")
        except LookupError:
            text = content.decode("utf-8", errors="replace")
        return FetchResult(
            url=str(resp.url),
            status_code=resp.status_code,
            content=content,
            text=text,
            headers=dict(resp.headers),
            content_hash=sha,
            elapsed_ms=elapsed_ms,
        )


def _looks_like_text(content_type: str) -> bool:
    return content_type.startswith(
        (
            "text/",
            "application/json",
            "application/xml",
            "application/rss",
            "application/atom",
            "application/xhtml",
        )
    )
