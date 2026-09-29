"""Centralised httpx client factory.

All outbound HTTP in this project should use one of these helpers so that:
  - SSL verification is ON by default for public internet APIs
  - Corporate / custom CA certs are honoured via SSL_CERT_FILE / REQUESTS_CA_BUNDLE
  - The dark-web / relaxed-cert path is opt-in and clearly labelled
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import httpx

from scry.config import get_settings


def _default_ua() -> str:
    """User-Agent from settings (some feeds block bot-like UAs)."""
    return get_settings().default_user_agent


def default_browser_headers() -> dict[str, str]:
    """Browser-like default headers for outbound HTTP.

    Some sources (e.g. CISA) sit behind WAFs that fingerprint the header
    *set*, not just the User-Agent: a bare UA string still gets a 403.
    Mimic a real browser's header set. Accept-Encoding is intentionally
    omitted so httpx advertises only the codecs it can actually decode.
    """
    return {
        "User-Agent": _default_ua(),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9," "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Upgrade-Insecure-Requests": "1",
    }


# Honour common env vars used by curl / requests / httpx for custom CA bundles
_CUSTOM_CA = (
    os.environ.get("SSL_CERT_FILE")
    or os.environ.get("REQUESTS_CA_BUNDLE")
    or os.environ.get("CURL_CA_BUNDLE")
)


def _ssl_context(relaxed: bool = False) -> bool | str | ssl.SSLContext:
    """Return the right ssl= argument for httpx.Client.

    relaxed=True: disable certificate verification (dark web / unknown CAs).
    relaxed=False: use custom CA bundle if set, otherwise system default.
    """
    if relaxed:
        return False
    if _CUSTOM_CA and Path(_CUSTOM_CA).exists():
        ctx = ssl.create_default_context(cafile=_CUSTOM_CA)
        return ctx
    return True


def build_client(
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    relaxed_ssl: bool = False,
    follow_redirects: bool = True,
) -> httpx.Client:
    """Create a synchronous httpx.Client with sensible defaults."""
    base_headers = default_browser_headers()
    if headers:
        base_headers.update(headers)
    return httpx.Client(
        headers=base_headers,
        timeout=httpx.Timeout(timeout),
        verify=_ssl_context(relaxed_ssl),
        follow_redirects=follow_redirects,
    )


def build_async_client(
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    relaxed_ssl: bool = False,
    follow_redirects: bool = True,
) -> httpx.AsyncClient:
    """Create an asynchronous httpx.AsyncClient with sensible defaults."""
    base_headers = default_browser_headers()
    if headers:
        base_headers.update(headers)
    return httpx.AsyncClient(
        headers=base_headers,
        timeout=httpx.Timeout(timeout),
        verify=_ssl_context(relaxed_ssl),
        follow_redirects=follow_redirects,
    )
