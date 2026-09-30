"""AbuseIPDB enricher.

Checks IPv4/IPv6 reputation via the AbuseIPDB v2 ``/check`` endpoint and
maps abuseConfidenceScore / country / ISP / report counts onto observable
enrichment fields plus suggested tags.

Free-tier API: 1000 checks/day. Responses are cached on disk so re-runs
don't burn quota; there is no configured rate knob so no limiter here.
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

logger = get_logger("abuseipdb")
BASE_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_DIR = Path(".cti_cache/abuseipdb")

_MALICIOUS_SCORE = 80
_SUSPICIOUS_SCORE = 50


@dataclass
class AbuseIPDBResult:
    ok: bool
    cached: bool
    fields: dict[str, Any]
    raw: dict[str, Any] | None = None
    error: str | None = None
    http_status: int | None = None


class AbuseIPDBEnricher(BaseEnricher):
    name = "abuseipdb"
    requires_network = True

    SUPPORTED_TYPES: ClassVar[set[str]] = {"ipv4", "ipv6"}

    def __init__(self, api_key: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.abuseipdb_api_key
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._client = (
            httpx.Client(
                timeout=httpx.Timeout(20.0),
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "Scry/0.1",
                },
            )
            if self.api_key
            else None
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ---- BaseEnricher contract ----

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        result = self.lookup(value)
        fields = result.fields
        tags: list[str] = []
        score = fields.get("abuse_confidence_score") or 0
        if fields and not fields.get("not_found"):
            if score >= _MALICIOUS_SCORE:
                tags.append("abuseipdb:malicious")
            elif score >= _SUSPICIOUS_SCORE:
                tags.append("abuseipdb:suspicious")
            if fields.get("total_reports"):
                tags.append("abuseipdb:reported")
        return EnrichmentOutput(
            fields={
                "abuseipdb": fields,
                "_abuseipdb_status": ("cached" if result.cached else ("ok" if result.ok else "error")),
            },
            rationale=[result.error] if result.error else [],
            tags=tags,
        )

    # ---- lookup ----

    def lookup(self, value: str) -> AbuseIPDBResult:
        if self._client is None or not self.api_key:
            return AbuseIPDBResult(False, False, {}, error="AbuseIPDB API key not configured")

        cache_path = _cache_path(value)
        if cache_path.exists():
            try:
                raw = json.loads(cache_path.read_text())
                return AbuseIPDBResult(True, True, _summarize(raw), raw=raw)
            except Exception:
                pass  # fall through to live lookup if cache is corrupted

        try:
            r = self._client.get(
                BASE_URL,
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": "false"},
            )
        except httpx.HTTPError as exc:
            return AbuseIPDBResult(False, False, {}, error=str(exc))

        if r.status_code == 404:
            payload = {"data": {"not_found": True}}
            cache_path.write_text(json.dumps(payload))
            return AbuseIPDBResult(True, False, {"not_found": True}, raw=payload)
        if r.status_code == 429:
            return AbuseIPDBResult(False, False, {}, error="rate limit (429)", http_status=429)
        if r.status_code >= 400:
            return AbuseIPDBResult(
                False, False, {}, error=f"HTTP {r.status_code}: {r.text[:200]}", http_status=r.status_code
            )

        try:
            raw = r.json()
        except Exception as exc:
            return AbuseIPDBResult(False, False, {}, error=f"json parse failed: {exc}")
        cache_path.write_text(json.dumps(raw))
        return AbuseIPDBResult(True, False, _summarize(raw), raw=raw)


def _cache_path(value: str) -> Path:
    key = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{key}.json"


def _summarize(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return {}
    data = raw.get("data")
    if not isinstance(data, dict):
        return {}
    if data.get("not_found"):
        return {"not_found": True}
    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        "num_distinct_users": data.get("numDistinctUsers"),
        "usage_type": data.get("usageType"),
    }
