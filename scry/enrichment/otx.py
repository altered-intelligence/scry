"""AlienVault OTX enricher.

Pulls pulse info, general reputation, and (for files) malware-analysis context
from the OTX /api/v1/indicators/<type>/<value> endpoints.

Public daily quota is generous but we still cache and rate-limit by default.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import httpx

from scry.config import get_settings
from scry.enrichment.base import BaseEnricher, EnrichmentOutput
from scry.logging import get_logger

logger = get_logger("otx")
BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
CACHE_DIR = Path(".cti_cache/otx")


_TYPE_TO_PATH = {
    "domain": "domain",
    "hostname": "hostname",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "url": "url",
    "md5": "file",
    "sha1": "file",
    "sha256": "file",
}


@dataclass
class OTXResult:
    ok: bool
    cached: bool
    fields: dict[str, Any]
    error: str | None = None
    http_status: int | None = None


class _SecondBucket:
    def __init__(self, per_sec: int) -> None:
        self.per_sec = max(1, per_sec)
        self.last: list[float] = []

    def wait_slot(self) -> None:
        now = time.monotonic()
        self.last = [t for t in self.last if now - t < 1.0]
        if len(self.last) >= self.per_sec:
            sleep_for = 1.0 - (now - self.last[0]) + 0.05
            if sleep_for > 0:
                time.sleep(sleep_for)
        self.last.append(time.monotonic())


class OTXEnricher(BaseEnricher):
    name = "otx"
    requires_network = True

    SUPPORTED_TYPES: ClassVar[set[str]] = set(_TYPE_TO_PATH.keys())

    def __init__(self, api_key: str | None = None) -> None:
        s = get_settings()
        self.api_key = api_key if api_key is not None else s.otx_api_key
        self.bucket = _SecondBucket(s.otx_rate_per_sec)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._client = (
            httpx.Client(
                timeout=httpx.Timeout(20.0),
                headers={"X-OTX-API-KEY": self.api_key, "User-Agent": "Scry/0.1"},
            )
            if self.api_key
            else None
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        ob_type = (context or {}).get("observable_type", "")
        result = self.lookup(value, ob_type)
        return EnrichmentOutput(
            fields={
                "otx": result.fields,
                "_otx_status": ("cached" if result.cached else ("ok" if result.ok else "error")),
            },
            rationale=[result.error] if result.error else [],
        )

    def lookup(self, value: str, observable_type: str, *, bypass_cache: bool = False) -> OTXResult:
        if self._client is None or not self.api_key:
            return OTXResult(False, False, {}, error="OTX API key not configured")
        ot = observable_type.lower()
        if ot not in self.SUPPORTED_TYPES:
            return OTXResult(False, False, {}, error=f"unsupported type {ot!r}")

        cache_path = _cache_path(ot, value)
        if not bypass_cache and cache_path.exists():
            try:
                raw = json.loads(cache_path.read_text())
                return OTXResult(True, True, _summarize(raw))
            except Exception:
                pass

        path = _TYPE_TO_PATH[ot]
        url = f"{BASE_URL}/{path}/{value}/general"
        self.bucket.wait_slot()
        try:
            r = self._client.get(url)
        except httpx.HTTPError as exc:
            return OTXResult(False, False, {}, error=str(exc))
        if r.status_code == 404:
            cache_path.write_text(json.dumps({"not_found": True}))
            return OTXResult(True, False, {"not_found": True})
        if r.status_code == 429:
            return OTXResult(False, False, {}, error="rate limit", http_status=429)
        if r.status_code >= 400:
            return OTXResult(False, False, {}, error=f"HTTP {r.status_code}", http_status=r.status_code)
        try:
            raw = r.json()
        except Exception as exc:
            return OTXResult(False, False, {}, error=f"json parse failed: {exc}")
        cache_path.write_text(json.dumps(raw))
        return OTXResult(True, False, _summarize(raw))


def _cache_path(ob_type: str, value: str) -> Path:
    key = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    (CACHE_DIR / ob_type).mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / ob_type / f"{key}.json"


def _summarize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return {}
    if raw.get("not_found"):
        return {"not_found": True}
    pulse_info = raw.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    top_pulses = [
        {
            "name": p.get("name"),
            "adversary": p.get("adversary") or None,
            "malware_families": [
                m.get("display_name") if isinstance(m, dict) else m for m in (p.get("malware_families") or [])
            ][:5],
            "tags": (p.get("tags") or [])[:8],
            "tlp": p.get("tlp"),
            "created": p.get("created"),
        }
        for p in pulses[:5]
    ]
    related_tags = pulse_info.get("references") or []
    out: dict[str, Any] = {
        "pulse_count": pulse_info.get("count") or len(pulses),
        "top_pulses": top_pulses,
        "related_tags": sorted({t for p in pulses for t in (p.get("tags") or [])})[:20],
        "malware_families": sorted(
            {
                (m.get("display_name") if isinstance(m, dict) else m)
                for p in pulses
                for m in (p.get("malware_families") or [])
            }
        )[:10],
        "adversaries": sorted({p.get("adversary") for p in pulses if p.get("adversary")})[:5],
        "references_count": len(related_tags),
    }
    if "reputation" in raw:
        out["reputation"] = raw.get("reputation")
    if "validation" in raw:
        out["validation"] = raw.get("validation")
    if "country_name" in raw:
        out["country"] = raw.get("country_name")
    if "asn" in raw:
        out["asn"] = raw.get("asn")
    if "type" in raw:
        out["indicator_type"] = raw.get("type")
    if "pe_info" in raw:
        out["pe_info"] = bool(raw.get("pe_info"))
    return out
