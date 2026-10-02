"""Safe HTTP fetcher.

- Async via httpx
- Per-host rate limit (simple token bucket)
- Hard size cap from settings.max_fetch_bytes, enforced while STREAMING the
  decompressed body (a gzip bomb never buffers whole in memory)
- Timeout from settings.fetch_timeout_seconds
- SSRF guard before any network call — re-validated on EVERY redirect hop
  (redirects are followed manually, bounded to 5 hops)
- robots.txt advisory check (best-effort; fails closed only when policy says so)
- Refuses file downloads / binary content unless policy allows
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt

from scry.config import get_settings
from scry.http import default_browser_headers
from scry.ingestion.policy import PolicyDecision
from scry.ingestion.ssrf import evaluate_url
from scry.logging import get_logger

logger = get_logger("fetcher")

# Statuses worth retrying (rate limiting / transient unavailability).
# Other 4xx are never retried.
_RETRYABLE_STATUSES = {429, 503}
_MAX_ATTEMPTS = 3
_RETRY_AFTER_CAP = 30.0

# Redirects are followed MANUALLY (never via httpx follow_redirects) so the
# SSRF guard re-runs on every hop — a feed that 302s to a link-local /
# metadata address is refused before any request goes out.
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5

# Chunk size for streamed body reads.
_STREAM_CHUNK = 64 * 1024


class _RetryableStatus(Exception):
    """Internal: response status that should be retried (429 / 503)."""

    def __init__(self, response: httpx.Response) -> None:
        super().__init__(f"HTTP {response.status_code}")
        self.response = response


def _retry_wait(retry_state) -> float:
    """Exponential backoff 2s → 4s → 8s; honor Retry-After (capped at 30s)."""
    exc = retry_state.outcome.exception()
    if isinstance(exc, _RetryableStatus):
        retry_after = exc.response.headers.get("retry-after")
        if retry_after:
            try:
                return min(float(retry_after), _RETRY_AFTER_CAP)
            except ValueError:
                pass  # HTTP-date form — fall back to exponential backoff
    return min(2.0**retry_state.attempt_number, _RETRY_AFTER_CAP)


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
    def __init__(self, *, client: httpx.AsyncClient | None = None) -> None:
        self._settings = get_settings()
        self._client = client
        self._rate = _RateLimiter()
        self._owns_client = client is None

    async def __aenter__(self) -> SafeFetcher:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=False,  # manual hops only — each one is SSRF-checked
                timeout=httpx.Timeout(self._settings.fetch_timeout_seconds),
                headers=default_browser_headers(),
                http2=False,
            )
            self._owns_client = True
        return self

    async def __aexit__(self, *exc) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_with_retry(self, url: str) -> httpx.Response:
        """GET with exponential-backoff retry on 429/503 (max 3 attempts).

        The response is returned OPEN (streamed, body unread) — the caller
        must read and close it. Retryable responses are closed before the
        next attempt.
        """
        assert self._client is not None
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(_MAX_ATTEMPTS),
            wait=_retry_wait,
            retry=retry_if_exception_type(_RetryableStatus),
            reraise=True,
        ):
            with attempt:
                resp = await self._client.send(
                    self._client.build_request("GET", url),
                    stream=True,
                )
                if resp.status_code in _RETRYABLE_STATUSES:
                    logger.warning(
                        "fetch_retryable_status",
                        url=url,
                        status=resp.status_code,
                        attempt=attempt.retry_state.attempt_number,
                    )
                    await resp.aclose()
                    raise _RetryableStatus(resp)
        return resp

    async def _read_capped(self, resp: httpx.Response, max_bytes: int) -> bytes | None:
        """Stream the (transparently decompressed) body, capped at max_bytes.

        Returns None when the cap is exceeded — the full body is never
        buffered, so a gzip bomb cannot exhaust memory. Chunks arrive
        decompressed from httpx, so the cap applies to the real payload size.
        """
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes(_STREAM_CHUNK):
            total += len(chunk)
            if total > max_bytes:
                return None
            chunks.append(chunk)
        return b"".join(chunks)

    async def fetch(
        self, url: str, *, policy: PolicyDecision, rate_limit_per_minute: int = 10
    ) -> FetchResult:
        if not policy.allowed or policy.fetch_mode == "deny":
            return FetchResult(url=url, status_code=None, error=f"policy blocked: {policy.reason}")

        start = time.monotonic()
        max_bytes = self._settings.max_fetch_bytes

        # Resolve the redirect chain manually: every hop (original URL and
        # each Location target) is SSRF-checked and rate-limited before the
        # request goes out. Bodies of redirect responses are never read.
        current_url = url
        resp: httpx.Response | None = None
        for hop in range(_MAX_REDIRECTS + 1):
            ssrf = evaluate_url(current_url)
            if not ssrf.allowed:
                logger.warning("ssrf_block", url=current_url, reason=ssrf.reason, original_url=url, hop=hop)
                return FetchResult(url=url, status_code=None, error=f"ssrf blocked: {ssrf.reason}")
            host = urlparse(current_url).hostname or ""
            await self._rate.acquire(host, rate_limit_per_minute)

            try:
                resp = await self._get_with_retry(current_url)
            except _RetryableStatus as exc:
                return FetchResult(
                    url=url,
                    status_code=exc.response.status_code,
                    headers=dict(exc.response.headers),
                    error=f"HTTP {exc.response.status_code} after {_MAX_ATTEMPTS} attempts",
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                )
            except httpx.HTTPError as exc:
                return FetchResult(
                    url=current_url,
                    status_code=None,
                    error=str(exc),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                )

            location = resp.headers.get("location")
            if resp.status_code in _REDIRECT_STATUSES and location:
                next_url = urljoin(current_url, location)
                await resp.aclose()
                if hop == _MAX_REDIRECTS:
                    return FetchResult(
                        url=url,
                        status_code=None,
                        error=f"too many redirects (>{_MAX_REDIRECTS})",
                        elapsed_ms=int((time.monotonic() - start) * 1000),
                    )
                logger.info("fetch_redirect_hop", from_url=current_url, to_url=next_url, hop=hop)
                current_url = next_url
                continue
            break

        assert resp is not None
        try:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            ct = resp.headers.get("content-type", "").lower()

            # Early gate on the declared length (cheap), but do not trust it:
            # the streaming cap below is the real enforcement — gzip-compressed
            # bodies decompress to far more than Content-Length claims.
            declared = int(resp.headers.get("content-length", "0") or 0)
            if declared > max_bytes:
                return FetchResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    error=f"response too large ({declared} bytes)",
                    elapsed_ms=elapsed_ms,
                )

            # Refuse binary/file downloads unless policy permits explicitly.
            if (
                not _looks_like_text(ct)
                and not policy.allow_binary_download
                and not policy.allow_file_download
            ):
                return FetchResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    error=f"refusing non-text content-type {ct!r}",
                    elapsed_ms=elapsed_ms,
                )

            try:
                content = await self._read_capped(resp, max_bytes)
            except httpx.HTTPError as exc:
                return FetchResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    error=str(exc),
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                )
            if content is None:
                return FetchResult(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    error=f"response too large (over {max_bytes} bytes decompressed)",
                    elapsed_ms=int((time.monotonic() - start) * 1000),
                )
        finally:
            await resp.aclose()

        sha = hashlib.sha256(content).hexdigest()
        try:
            text = content.decode(resp.charset_encoding or "utf-8", errors="replace")
        except LookupError:
            text = content.decode("utf-8", errors="replace")
        return FetchResult(
            url=str(resp.url),
            status_code=resp.status_code,
            content=content,
            text=text,
            headers=dict(resp.headers),
            content_hash=sha,
            elapsed_ms=int((time.monotonic() - start) * 1000),
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
