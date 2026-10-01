"""FIRST.org EPSS enricher (v0.8.0 step 2).

EPSS (Exploit Prediction Scoring System) is a free, keyless API from FIRST.org
that scores the probability a CVE will be exploited in the wild within the
next 30 days, together with a percentile rank against all scored CVEs.

    https://api.first.org/data/v1/epss?cve=CVE-2021-44228

The endpoint accepts comma-joined batches (``cve=CVE-1,CVE-2``); we cap
requests at ``BATCH_SIZE`` CVEs. Self-imposed politeness rate limit: at most
one request every ``min_interval`` seconds (the API is free and unauthenticated
— we keep the pace gentle anyway).

Unlike VT/OTX/AbuseIPDB/GreyNoise this provider needs NO API key and no
per-user key concept; it always runs during batch enrichment.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from scry.enrichment.base import BaseEnricher, EnrichmentError, EnrichmentOutput
from scry.logging import get_logger

logger = get_logger("epss")
BASE_URL = "https://api.first.org/data/v1/epss"


@dataclass
class EpsRecord:
    cve_id: str
    epss: float
    percentile: float


@dataclass
class EpsBatchResult:
    ok: bool
    records: dict[str, EpsRecord]
    # Requested CVE ids absent from the response (unknown / never scored by
    # EPSS). Callers should mark these as checked-without-data so they are
    # not re-queried forever.
    not_found: list[str]
    error: str | None = None
    http_status: int | None = None


class _IntervalLimiter:
    """Enforce a minimum interval between consecutive requests."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last: float | None = None

    def wait_slot(self) -> None:
        now = time.monotonic()
        if self._last is not None:
            sleep_for = self.min_interval - (now - self._last)
            if sleep_for > 0:
                logger.info("epss_rate_sleep", seconds=round(sleep_for, 2))
                time.sleep(sleep_for)
        self._last = time.monotonic()


class EpsEnricher(BaseEnricher):
    name = "epss"
    requires_network = True

    # FIRST.org accepts larger batches; 30 keeps request URLs and response
    # sizes modest and matches the per-run caps elsewhere in the engine.
    BATCH_SIZE = 30

    def __init__(self, min_interval: float = 2.0) -> None:
        self.limiter = _IntervalLimiter(min_interval)
        self._client = httpx.Client(
            timeout=httpx.Timeout(20.0),
            headers={"Accept": "application/json", "User-Agent": "Scry/0.1"},
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ---- BaseEnricher contract (single CVE id) ----

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        cve_id = (context or {}).get("cve_id", value)
        try:
            result = self.enrich_batch([cve_id])
        except EnrichmentError as exc:
            return EnrichmentOutput(fields={"epss": {}, "_epss_status": "error"}, rationale=[str(exc)])
        if not result.ok:
            return EnrichmentOutput(
                fields={"epss": {}, "_epss_status": "error"}, rationale=[result.error or "epss error"]
            )
        rec = result.records.get(cve_id)
        if rec is None:
            return EnrichmentOutput(
                fields={"epss": {"not_found": True}, "_epss_status": "not_found"},
                rationale=[f"{cve_id} not scored by EPSS"],
            )
        return EnrichmentOutput(
            fields={
                "epss": {"epss": rec.epss, "percentile": rec.percentile},
                "_epss_status": "ok",
            },
            rationale=[f"EPSS {rec.epss:.4f} (percentile {rec.percentile:.4f})"],
        )

    # ---- batched lookup ----

    def enrich_batch(self, cve_ids: list[str]) -> EpsBatchResult:
        """Look up one batch of CVE ids (chunked to ``BATCH_SIZE`` per request).

        Raises EnrichmentError on HTTP/transport/parse failures; an unknown
        CVE is NOT an error — it lands in ``not_found``.
        """
        records: dict[str, EpsRecord] = {}
        not_found: list[str] = []
        ids = [c for c in cve_ids if c]
        for start in range(0, len(ids), self.BATCH_SIZE):
            chunk = ids[start : start + self.BATCH_SIZE]
            raw = self._request(chunk)
            found = _parse_records(raw)
            records.update(found)
            not_found.extend(c for c in chunk if c not in found)
        return EpsBatchResult(ok=True, records=records, not_found=not_found)

    def _request(self, cve_ids: list[str]) -> dict[str, Any]:
        params = {"cve": ",".join(cve_ids)}
        self.limiter.wait_slot()
        try:
            r = self._client.get(BASE_URL, params=params)
        except httpx.HTTPError as exc:
            raise EnrichmentError(f"EPSS request failed: {exc}") from exc
        if r.status_code == 404:
            return {"data": []}
        if r.status_code >= 400:
            raise EnrichmentError(f"EPSS HTTP {r.status_code}: {r.text[:200]}")
        try:
            raw = r.json()
        except Exception as exc:
            raise EnrichmentError(f"EPSS json parse failed: {exc}") from exc
        if not isinstance(raw, dict):
            raise EnrichmentError("EPSS response was not a JSON object")
        return raw


def _parse_records(raw: dict[str, Any]) -> dict[str, EpsRecord]:
    """Map ``data[]`` entries (epss/percentile arrive as strings) to records."""
    out: dict[str, EpsRecord] = {}
    data = raw.get("data") or []
    if not isinstance(data, list):
        return out
    for entry in data:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cve")
        if not cve_id:
            continue
        try:
            out[str(cve_id)] = EpsRecord(
                cve_id=str(cve_id),
                epss=float(entry["epss"]),
                percentile=float(entry["percentile"]),
            )
        except (KeyError, TypeError, ValueError):
            logger.warning("epss_bad_entry", entry=str(entry)[:200])
    return out
