"""GreyNoise enricher.

Classifies IPv4/IPv6 addresses via the GreyNoise community API
(``/v3/community/{ip}``): whether the IP is internet "noise", whether it
belongs to a known benign service (RIOT), and a malicious/benign/unknown
classification. Mapped onto observable enrichment fields plus suggested tags.

The community endpoint accepts an optional key header; it is sent when
``greynoise_api_key`` is configured. Responses are cached on disk.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import httpx

from scry.config import get_settings
from scry.enrichment.base import BaseEnricher, EnrichmentOutput
from scry.logging import get_logger

logger = get_logger("greynoise")
BASE_URL = "https://api.greynoise.io/v3/community"
CACHE_DIR = Path(".cti_cache/greynoise")


@dataclass
class GreyNoiseResult:
    ok: bool
    cached: bool
    fields: dict[str, Any]
    raw: dict[str, Any] | None = None
    error: str | None = None
    http_status: int | None = None


class GreyNoiseEnricher(BaseEnricher):
    name = "greynoise"
    requires_network = True

    SUPPORTED_TYPES: ClassVar[set[str]] = {"ipv4", "ipv6"}

    def __init__(self, api_key: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.greynoise_api_key
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        headers = {"Accept": "application/json", "User-Agent": "Scry/0.1"}
        if self.api_key:
            headers["key"] = self.api_key
        self._client = httpx.Client(timeout=httpx.Timeout(20.0), headers=headers)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ---- BaseEnricher contract ----

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        result = self.lookup(value)
        fields = result.fields
        tags: list[str] = []
        classification = fields.get("classification")
        if classification == "malicious":
            tags.append("greynoise:malicious")
        elif classification == "benign":
            tags.append("greynoise:benign")
        if fields.get("riot"):
            tags.append("greynoise:riot")
        elif fields.get("noise"):
            tags.append("greynoise:noise")
        return EnrichmentOutput(
            fields={
                "greynoise": fields,
                "_greynoise_status": ("cached" if result.cached else ("ok" if result.ok else "error")),
            },
            rationale=[result.error] if result.error else [],
            tags=tags,
        )

    # ---- lookup ----

    def lookup(self, value: str) -> GreyNoiseResult:
        if not self.api_key:
            return GreyNoiseResult(False, False, {}, error="GreyNoise API key not configured")

        cache_path = _cache_path(value)
        if cache_path.exists():
            try:
                raw = json.loads(cache_path.read_text())
                return GreyNoiseResult(True, True, _summarize(raw), raw=raw)
            except Exception:
                pass  # fall through to live lookup if cache is corrupted

        try:
            r = self._client.get(f"{BASE_URL}/{value}")
        except httpx.HTTPError as exc:
            return GreyNoiseResult(False, False, {}, error=str(exc))

        if r.status_code == 404:
            payload = {"not_found": True}
            cache_path.write_text(json.dumps(payload))
            return GreyNoiseResult(True, False, {"not_found": True}, raw=payload)
        if r.status_code == 429:
            return GreyNoiseResult(False, False, {}, error="rate limit (429)", http_status=429)
        if r.status_code >= 400:
            return GreyNoiseResult(
                False, False, {}, error=f"HTTP {r.status_code}: {r.text[:200]}", http_status=r.status_code
            )

        try:
            raw = r.json()
        except Exception as exc:
            return GreyNoiseResult(False, False, {}, error=f"json parse failed: {exc}")

        # "IP not observed" is a normal negative answer — cache it too.
        if isinstance(raw, dict) and raw.get("message") == "IP not observed":
            payload = {"not_found": True}
            cache_path.write_text(json.dumps(payload))
            return GreyNoiseResult(True, False, {"not_found": True}, raw=payload)

        cache_path.write_text(json.dumps(raw))
        return GreyNoiseResult(True, False, _summarize(raw), raw=raw)


def _cache_path(value: str) -> Path:
    key = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{key}.json"


def _summarize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return {}
    if raw.get("not_found"):
        return {"not_found": True}
    return {
        "noise": bool(raw.get("noise")),
        "riot": bool(raw.get("riot")),
        "classification": raw.get("classification"),
        "name": raw.get("name"),
        "last_seen": raw.get("last_seen"),
        "link": raw.get("link"),
        "message": raw.get("message"),
    }
