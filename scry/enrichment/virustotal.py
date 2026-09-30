"""VirusTotal v3 enricher.

Looks up reputation for domains, URLs, IPv4/IPv6 addresses, and file hashes
(MD5/SHA1/SHA256). Stores responses to a local disk cache so re-runs and
crashes don't burn quota.

Public-tier API: 4 req/min, 500/day. The token-bucket limiter respects the
per-minute side; the daily quota (vt_daily_quota) is enforced by an
in-memory counter that resets at UTC midnight.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import httpx

from scry.config import get_settings
from scry.enrichment.base import BaseEnricher, EnrichmentOutput
from scry.enrichment.ratelimit import DailyQuota
from scry.logging import get_logger

logger = get_logger("vt")
BASE_URL = "https://www.virustotal.com/api/v3"
CACHE_DIR = Path(".cti_cache/vt")


@dataclass
class VTResult:
    ok: bool
    cached: bool
    fields: dict[str, Any]
    raw: dict[str, Any] | None = None
    error: str | None = None
    http_status: int | None = None


class _MinuteBucket:
    def __init__(self, per_min: int) -> None:
        self.per_min = max(1, per_min)
        self.history: list[float] = []

    def wait_slot(self) -> None:
        now = time.monotonic()
        self.history = [t for t in self.history if now - t < 60.0]
        if len(self.history) >= self.per_min:
            sleep_for = 60.0 - (now - self.history[0]) + 0.2
            if sleep_for > 0:
                logger.info("vt_rate_sleep", seconds=round(sleep_for, 2))
                time.sleep(sleep_for)
            self.history = [t for t in self.history if (time.monotonic() - t) < 60.0]
        self.history.append(time.monotonic())


class VirusTotalEnricher(BaseEnricher):
    name = "virustotal"
    requires_network = True

    SUPPORTED_TYPES: ClassVar[set[str]] = {"domain", "url", "ipv4", "ipv6", "sha256", "sha1", "md5"}

    def __init__(self, api_key: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key if api_key is not None else settings.virustotal_api_key
        self.bucket = _MinuteBucket(settings.vt_rate_per_min)
        self.daily = DailyQuota(settings.vt_daily_quota)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._client = (
            httpx.Client(
                timeout=httpx.Timeout(20.0),
                headers={"x-apikey": self.api_key, "User-Agent": "Scry/0.1"},
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
        ob_type = (context or {}).get("observable_type", "")
        result = self.lookup(value, ob_type)
        return EnrichmentOutput(
            fields={
                "virustotal": result.fields,
                "_vt_status": ("cached" if result.cached else ("ok" if result.ok else "error")),
            },
            confidence_delta=0,
            rationale=[result.error] if result.error else [],
        )

    # ---- lookup dispatcher ----

    def lookup(self, value: str, observable_type: str) -> VTResult:
        if self._client is None or not self.api_key:
            return VTResult(False, False, {}, error="VT API key not configured")
        ot = observable_type.lower()
        if ot not in self.SUPPORTED_TYPES:
            return VTResult(False, False, {}, error=f"unsupported type {ot!r}")

        cache_path = _cache_path(ot, value)
        if cache_path.exists():
            try:
                raw = json.loads(cache_path.read_text())
                return VTResult(True, True, _summarize(ot, raw), raw=raw)
            except Exception:
                pass  # fall through to live lookup if cache is corrupted

        if not self.daily.consume():
            return VTResult(False, False, {}, error="daily quota exhausted", http_status=429)

        endpoint = _endpoint_for(ot, value)
        self.bucket.wait_slot()
        try:
            r = self._client.get(f"{BASE_URL}{endpoint}")
        except httpx.HTTPError as exc:
            return VTResult(False, False, {}, error=str(exc))

        if r.status_code == 404:
            # not seen by VT — store a small negative marker so we don't re-query
            payload = {"data": {"attributes": {"not_found": True}}}
            cache_path.write_text(json.dumps(payload))
            return VTResult(True, False, {"not_found": True}, raw=payload)
        if r.status_code == 429:
            return VTResult(False, False, {}, error="rate limit (429)", http_status=429)
        if r.status_code >= 400:
            return VTResult(
                False, False, {}, error=f"HTTP {r.status_code}: {r.text[:200]}", http_status=r.status_code
            )

        try:
            raw = r.json()
        except Exception as exc:
            return VTResult(False, False, {}, error=f"json parse failed: {exc}")
        cache_path.write_text(json.dumps(raw))
        return VTResult(True, False, _summarize(ot, raw), raw=raw)


def _cache_path(ob_type: str, value: str) -> Path:
    key = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    (CACHE_DIR / ob_type).mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / ob_type / f"{key}.json"


def _endpoint_for(ob_type: str, value: str) -> str:
    if ob_type == "domain":
        return f"/domains/{value}"
    if ob_type in {"sha256", "sha1", "md5"}:
        return f"/files/{value}"
    if ob_type == "ipv4" or ob_type == "ipv6":
        return f"/ip_addresses/{value}"
    if ob_type == "url":
        url_id = base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")
        return f"/urls/{url_id}"
    raise ValueError(f"unsupported VT type {ob_type!r}")


def _summarize(ob_type: str, raw: dict) -> dict:
    """Pull the analyst-relevant fields out of the (very verbose) VT response."""
    if not isinstance(raw, dict):
        return {}
    data = raw.get("data") or {}
    attrs = (data.get("attributes") or {}) if isinstance(data, dict) else {}
    if attrs.get("not_found"):
        return {"not_found": True}

    out: dict[str, Any] = {}
    stats = attrs.get("last_analysis_stats") or {}
    out["last_analysis_stats"] = stats
    out["malicious"] = int(stats.get("malicious") or 0)
    out["suspicious"] = int(stats.get("suspicious") or 0)
    out["harmless"] = int(stats.get("harmless") or 0)
    out["undetected"] = int(stats.get("undetected") or 0)
    out["reputation"] = attrs.get("reputation")
    out["last_analysis_date"] = attrs.get("last_analysis_date")
    out["categories"] = attrs.get("categories")
    out["tags"] = attrs.get("tags")
    if ob_type in {"sha256", "sha1", "md5"}:
        out["meaningful_name"] = attrs.get("meaningful_name")
        out["names"] = (attrs.get("names") or [])[:10]
        out["type_description"] = attrs.get("type_description")
        out["size"] = attrs.get("size")
        out["popular_threat_classification"] = attrs.get("popular_threat_classification")
    if ob_type == "domain":
        out["registrar"] = attrs.get("registrar")
        out["creation_date"] = attrs.get("creation_date")
        out["last_dns_records"] = (attrs.get("last_dns_records") or [])[:5]
        out["whois"] = (attrs.get("whois") or "")[:500] or None
    if ob_type in {"ipv4", "ipv6"}:
        out["asn"] = attrs.get("asn")
        out["as_owner"] = attrs.get("as_owner")
        out["country"] = attrs.get("country")
        out["network"] = attrs.get("network")
    if ob_type == "url":
        out["final_url"] = attrs.get("last_final_url")
        out["title"] = attrs.get("title")
    return out
