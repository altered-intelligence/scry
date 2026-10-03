"""FortiGuard Labs IOC Research API (v1) client + enricher.

Implements the full FortiGuard IOC Research API surface (guide v1.6):

General:      /v1/threat_intel_search, /v1/related_indicators_search,
              /v1/country_visit_count
Submission:   POST /v1/user_submission, GET /v1/user_submission/{id}
Investigation URL:  /v1/url batch + threatinfo / riskinfo / countryvisitcounts
                    / aggregatecountryvisitcounts / aisummary
Investigation IP:   /v1/ip batch + asn / geoip / isdb / ptr / whois / aisummary
Investigation Domain: /v1/domain batch + getips / whois
Investigation File: /v1/file batch + threatinfo / aisummary
Outbreak:     /v1/outbreak_tags, /v1/outbreak_tag_ioc_search,
              /v1/outbreak_tag_telemetry

Auth: `api_key` HTTP header on every request. Research-use API with quotas —
the enricher caches results and rate-limits by default.

The enricher integrates with the standard enrichment engine via the
threat_intel_search endpoint (one call returns categories, IOC rating, tags,
confidence, kill-chain phases, and a reference URL).
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
from scry.enrichment.base import BaseEnricher, EnrichmentError, EnrichmentOutput
from scry.logging import get_logger

logger = get_logger("fortiguard")

BASE_URL = "https://ioc-api.fortiguard.com"
CACHE_DIR = Path(".cti_cache/fortiguard")

# Observable type -> FortiGuard threat_intel_search `type` parameter
# (omitted = auto-detect; we pass it explicitly to avoid ambiguous guesses).
_TYPE_TO_PARAM = {
    "domain": "domain",
    "url": "url",
    "ipv4": "ip",
    "ipv6": "ip",
    "md5": "filehash",
    "sha1": "filehash",
    "sha256": "filehash",
    "email": "email",
    "onion": "url",
}


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


class FortiGuardClient:
    """Thin typed wrapper over every FortiGuard IOC Research API endpoint."""

    def __init__(self, api_key: str, *, rate_per_sec: int | None = None) -> None:
        if not api_key:
            raise ValueError("FortiGuard API key required")
        s = get_settings()
        self.api_key = api_key
        self.bucket = _SecondBucket(rate_per_sec or s.fortiguard_rate_per_sec)
        self._client = httpx.Client(
            timeout=httpx.Timeout(30.0),
            headers={"api_key": api_key, "User-Agent": "Scry/0.1"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> FortiGuardClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: dict | None = None,
        data: dict | None = None,
        files: dict | None = None,
    ) -> Any:
        self.bucket.wait_slot()
        r = self._client.request(
            method, f"{BASE_URL}{path}", params=params, json=json_body, data=data, files=files
        )
        if r.status_code == 404:
            return None  # NotFoundError — caller distinguishes "no data"
        if r.status_code == 429:
            raise EnrichmentError("FortiGuard quota exceeded (HTTP 429)")
        if r.status_code == 403:
            raise EnrichmentError("FortiGuard unauthorized (HTTP 403) — check API key")
        if r.status_code >= 400:
            raise EnrichmentError(f"FortiGuard HTTP {r.status_code}: {r.text[:200]}")
        try:
            return r.json()
        except Exception as exc:
            raise EnrichmentError(f"FortiGuard JSON parse failed: {exc}") from exc

    # --- General APIs ------------------------------------------------------
    def threat_intel_search(self, indicator: str, type: str | None = None) -> dict | None:
        params: dict[str, Any] = {"indicator": indicator}
        if type:
            params["type"] = type
        return self._request("GET", "/v1/threat_intel_search", params=params)

    def related_indicators(self, indicator: str, type: str | None = None) -> list | None:
        params: dict[str, Any] = {"indicator": indicator}
        if type:
            params["type"] = type
        return self._request("GET", "/v1/related_indicators_search", params=params)

    def country_visit_count(self, host: str, start: str | None = None, end: str | None = None) -> dict | None:
        params: dict[str, Any] = {"host": host}
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        return self._request("GET", "/v1/country_visit_count", params=params)

    # --- Submission APIs ---------------------------------------------------
    def submit_ioc(
        self,
        subject: str,
        description: str,
        *,
        tags: list[str] | None = None,
        category: str = "ioc",
        tlp: str = "red",
        cc_emails: list[str] | None = None,
        upload_file: str | Path | None = None,
    ) -> str:
        if category not in {"ioc", "fp"}:
            raise ValueError("category must be 'ioc' or 'fp'")
        if tlp not in {"white", "green", "amber", "red"}:
            raise ValueError("tlp must be white/green/amber/red")
        data: dict[str, Any] = {
            "subject": subject,
            "description": description,
            "category": category,
            "tlp": tlp,
        }
        if tags:
            data["tags"] = ",".join(tags)
        if cc_emails:
            data["cc_emails"] = ",".join(cc_emails)
        files = None
        if upload_file is not None:
            p = Path(upload_file)
            files = {"upload_file": (p.name, p.open("rb"))}
        try:
            r = self._client.post(
                f"{BASE_URL}/v1/user_submission", data=data, files=files, headers={"api_key": self.api_key}
            )
        finally:
            if files:
                files["upload_file"][1].close()
        if r.status_code != 200:
            raise EnrichmentError(f"FortiGuard submission failed HTTP {r.status_code}: {r.text[:200]}")
        # Response body is the submission page URL per the guide.
        return r.text.strip().strip('"')

    def submission_status(self, submission_id: str) -> dict | None:
        return self._request("GET", f"/v1/user_submission/{submission_id}")

    # --- Investigation: URL -------------------------------------------------
    def url_batch(self, urls: list[str], fields: list[str]) -> dict | None:
        _validate_fields(fields, {"threatinfo", "riskinfo", "countryvisitcounts", "aisummary"})
        return self._request("POST", "/v1/url", json_body={"fields": fields, "urls": urls})

    def url_threatinfo(self, url: str) -> dict | None:
        return self._request("GET", "/v1/url/threatinfo", params={"url": url})

    def url_riskinfo(self, url: str) -> dict | None:
        return self._request("GET", "/v1/url/riskinfo", params={"url": url})

    def url_country_visits(
        self, url: str, start_date: str | None = None, end_date: str | None = None
    ) -> dict | None:
        params: dict[str, Any] = {"url": url}
        if start_date:
            params["startDate"] = start_date
        if end_date:
            params["endDate"] = end_date
        return self._request("GET", "/v1/url/countryvisitcounts", params=params)

    def url_aggregate_visits(
        self, urls: list[str], start_date: str | None = None, end_date: str | None = None
    ) -> dict | None:
        body: dict[str, Any] = {"urls": urls}
        if start_date:
            body["startDate"] = start_date
        if end_date:
            body["endDate"] = end_date
        return self._request("POST", "/v1/url/aggregatecountryvisitcounts", json_body=body)

    def url_ai_summary(self, url: str) -> dict | None:
        return self._request("GET", "/v1/url/aisummary", params={"url": url})

    # --- Investigation: IP --------------------------------------------------
    def ip_batch(self, ips: list[str], fields: list[str]) -> dict | None:
        _validate_fields(fields, {"asn", "geoip", "isdb", "ptr", "whois", "aisummary"})
        return self._request("POST", "/v1/ip", json_body={"fields": fields, "ips": ips})

    def ip_asn(self, ip: str) -> dict | None:
        return self._request("GET", "/v1/ip/asn", params={"ip": ip})

    def ip_geoip(self, ip: str) -> dict | None:
        return self._request("GET", "/v1/ip/geoip", params={"ip": ip})

    def ip_isdb(self, ip: str) -> dict | None:
        return self._request("GET", "/v1/ip/isdb", params={"ip": ip})

    def ip_ptr(self, ip: str) -> dict | None:
        return self._request("GET", "/v1/ip/ptr", params={"ip": ip})

    def ip_whois(self, ip: str) -> dict | None:
        return self._request("GET", "/v1/ip/whois", params={"ip": ip})

    def ip_ai_summary(self, ip: str) -> dict | None:
        return self._request("GET", "/v1/ip/aisummary", params={"ip": ip})

    # --- Investigation: Domain ----------------------------------------------
    def domain_batch(self, domains: list[str], fields: list[str]) -> dict | None:
        _validate_fields(fields, {"getips", "whois"})
        return self._request("POST", "/v1/domain", json_body={"fields": fields, "urls": domains})

    def domain_getips(self, domain: str, limit: int | None = None) -> list | None:
        params: dict[str, Any] = {"domain": domain}
        if limit:
            params["limit"] = limit
        return self._request("GET", "/v1/domain/getips", params=params)

    def domain_whois(self, domain: str) -> dict | None:
        return self._request("GET", "/v1/domain/whois", params={"domain": domain})

    # --- Investigation: File -------------------------------------------------
    def file_batch(self, hashes: list[str], fields: list[str]) -> dict | None:
        _validate_fields(fields, {"threatinfo", "aisummary"})
        return self._request("POST", "/v1/file", json_body={"fields": fields, "files": hashes})

    def file_threatinfo(self, file_hash: str) -> dict | None:
        return self._request("GET", "/v1/file/threatinfo", params={"file": file_hash})

    def file_ai_summary(self, file_hash: str) -> dict | None:
        return self._request("GET", "/v1/file/aisummary", params={"file": file_hash})

    # --- Outbreak alerts ------------------------------------------------------
    def outbreak_tags(self, tag: str | None = None) -> Any:
        params = {"tag": tag} if tag else None
        return self._request("GET", "/v1/outbreak_tags", params=params)

    def outbreak_iocs(self, tag: str) -> list | None:
        return self._request("GET", "/v1/outbreak_tag_ioc_search", params={"tag": tag})

    def outbreak_telemetry(self, tag: str, date: str | None = None) -> dict | None:
        params: dict[str, Any] = {"tag": tag}
        if date:
            params["date"] = date
        return self._request("GET", "/v1/outbreak_tag_telemetry", params=params)


def _validate_fields(fields: list[str], allowed: set[str]) -> None:
    bad = set(fields) - allowed
    if bad:
        raise ValueError(f"unsupported field(s) {sorted(bad)}; allowed: {sorted(allowed)}")


@dataclass
class FortiGuardResult:
    ok: bool
    cached: bool
    fields: dict[str, Any]
    error: str | None = None
    http_status: int | None = None


class FortiGuardEnricher(BaseEnricher):
    """Engine-integrated enricher backed by /v1/threat_intel_search."""

    name = "fortiguard"
    requires_network = True

    SUPPORTED_TYPES: ClassVar[set[str]] = set(_TYPE_TO_PARAM.keys())

    def __init__(self, api_key: str | None = None) -> None:
        s = get_settings()
        self.api_key = api_key if api_key is not None else s.fortiguard_api_key
        self._client: FortiGuardClient | None = FortiGuardClient(self.api_key) if self.api_key else None

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        ob_type = (context or {}).get("observable_type", "")
        result = self.lookup(value, ob_type)
        out: dict[str, Any] = {
            "fortiguard": result.fields,
            "_fortiguard_status": ("cached" if result.cached else ("ok" if result.ok else "error")),
        }
        tags: list[str] = []
        conf = str(result.fields.get("confidence", "")).lower()
        if conf == "high":
            tags.append("fortiguard:malicious")
        elif conf == "medium":
            tags.append("fortiguard:suspicious")
        return EnrichmentOutput(
            fields=out,
            rationale=[result.error] if result.error else [],
            tags=tags,
        )

    def lookup(self, value: str, observable_type: str, *, bypass_cache: bool = False) -> FortiGuardResult:
        if self._client is None or not self.api_key:
            return FortiGuardResult(False, False, {}, error="FortiGuard API key not configured")
        ot = observable_type.lower()
        if ot not in self.SUPPORTED_TYPES:
            return FortiGuardResult(False, False, {}, error=f"unsupported type {ot!r}")

        cache_path = _cache_path(ot, value)
        if not bypass_cache and cache_path.exists():
            try:
                raw = json.loads(cache_path.read_text())
                return FortiGuardResult(True, True, _summarize(raw))
            except Exception:
                pass

        assert self._client is not None
        try:
            raw = self._client.threat_intel_search(value, _TYPE_TO_PARAM[ot])
        except EnrichmentError as exc:
            status = 429 if "429" in str(exc) else 403 if "403" in str(exc) else None
            return FortiGuardResult(False, False, {}, error=str(exc), http_status=status)
        except Exception as exc:  # transport etc.
            return FortiGuardResult(False, False, {}, error=str(exc))

        if raw is None:
            cache_path.write_text(json.dumps({"not_found": True}))
            return FortiGuardResult(True, False, {"not_found": True})
        cache_path.write_text(json.dumps(raw))
        return FortiGuardResult(True, False, _summarize(raw))


def _cache_path(ob_type: str, value: str) -> Path:
    key = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    (CACHE_DIR / ob_type).mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / ob_type / f"{key}.json"


def _summarize(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    if raw.get("not_found"):
        return {"not_found": True}
    out: dict[str, Any] = {}
    for key in (
        "wf_cate",
        "av_cate",
        "ioc_cate",
        "confidence",
        "reference_url",
        "created",
        "modified",
    ):
        if raw.get(key):
            out[key] = raw[key]
    if raw.get("spam_cates"):
        out["spam_cates"] = raw["spam_cates"]
    if raw.get("ioc_tags"):
        out["ioc_tags"] = raw["ioc_tags"]
    if raw.get("kill_chain_phases"):
        out["kill_chain_phases"] = raw["kill_chain_phases"]
    return out
