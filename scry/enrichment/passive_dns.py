"""crt.sh passive-DNS / certificate-transparency enricher (v0.8.0 step 3).

Queries crt.sh (https://crt.sh) — a free, public, UNAUTHENTICATED search
engine over certificate-transparency logs. For a domain it returns every
logged certificate whose name list matches ``%.<domain>``; each entry's
``name_value`` may itself carry several newline-separated SANs.

PASSIVE ONLY — this stays strictly inside the SECURITY.md boundary: public
certificate-transparency logs, no active scanning, no DNS resolution of the
target domain, and no connection of any kind to the target itself. The only
network peer is crt.sh.

crt.sh is a free public service and can be slow: we use a generous 60 s
timeout and treat a timeout as a SKIP (retry on a later run), never a hard
failure. Self-imposed politeness: at most one request every ``min_interval``
seconds (default 2 s) inside a run — the service is shared and unthrottled
upstream, so we keep the pace gentle.

Unlike VT/OTX/AbuseIPDB/GreyNoise this provider needs NO API key and no
per-user key concept; it always runs during batch enrichment, like EPSS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from scry.enrichment.base import BaseEnricher, EnrichmentError, EnrichmentOutput
from scry.enrichment.epss import _IntervalLimiter
from scry.logging import get_logger

logger = get_logger("passive_dns")
BASE_URL = "https://crt.sh/"


@dataclass
class PassiveDnsResult:
    """Outcome of one crt.sh lookup.

    ``ok`` is True when the request completed — a domain simply absent from
    the CT logs is still ``ok`` with ``count == 0`` (the engine stores that
    as a checked-but-empty sentinel so it is not re-queried until the TTL).
    A timeout is NOT an error: ``ok`` is False and ``skipped_reason`` says
    why, so the engine counts it as a skip and retries next run.
    """

    ok: bool
    count: int = 0
    samples: list[str] = field(default_factory=list)
    skipped_reason: str | None = None


def parse_subdomains(raw: Any, domain: str) -> list[str]:
    """Distinct SAN names under ``domain`` from a crt.sh JSON response.

    crt.sh returns a JSON array of ``{name_value, ...}`` entries where
    ``name_value`` may contain several newline-separated names per
    certificate. Names are lowercased, wildcard ``*.`` prefixes stripped,
    deduped, and filtered to names strictly under the queried domain — the
    bare queried domain itself is dropped (we want subdomains, not the
    domain we already know). Returns the sorted full set (the caller caps
    the stored samples).
    """
    if not isinstance(raw, list):
        raise EnrichmentError("crt.sh response was not a JSON array")
    bare = domain.lower().rstrip(".")
    names: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value")
        if not isinstance(value, str):
            continue
        for name in value.split("\n"):
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or name == bare:
                continue
            if not name.endswith("." + bare):
                continue  # unrelated name sharing the same certificate
            names.add(name)
    return sorted(names)


class PassiveDnsEnricher(BaseEnricher):
    name = "passive_dns"
    requires_network = True

    # How many sample subdomains we keep stored per domain.
    MAX_SAMPLES = 25

    def __init__(self, min_interval: float = 2.0, timeout: float = 60.0) -> None:
        self.limiter = _IntervalLimiter(min_interval)
        # crt.sh is slow more often than not; 60 s is deliberate. A timeout
        # is a skip, not an error (see module docstring).
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            headers={"Accept": "application/json", "User-Agent": "Scry/0.1"},
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    # ---- BaseEnricher contract (single domain) ----

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        domain = value.lower().rstrip(".")
        result = self.lookup(domain)
        if result.skipped_reason:
            note = f"crt.sh {result.skipped_reason}; skipped (will retry on a later run)"
            return EnrichmentOutput(
                fields={"_passive_dns_status": "skipped", "passive_dns_note": note},
                rationale=[note],
            )
        return EnrichmentOutput(
            fields={
                "passive_dns_count": result.count,
                "passive_dns_samples": result.samples,
                "passive_dns_enriched_at": datetime.now(UTC).isoformat(),
                "_passive_dns_status": "ok",
            },
            rationale=[f"crt.sh: {result.count} distinct SAN name(s) under {domain}"],
        )

    # ---- single-domain lookup ----

    def lookup(self, domain: str) -> PassiveDnsResult:
        """One crt.sh request for ``domain``.

        Timeout → ``PassiveDnsResult(ok=False, skipped_reason="timeout")``
        (skip, not error). HTTP/transport/parse failures raise
        ``EnrichmentError`` — the engine records those as run errors and
        keeps going.
        """
        domain = domain.lower().rstrip(".")
        self.limiter.wait_slot()
        try:
            r = self._client.get(BASE_URL, params={"q": f"%.{domain}", "output": "json"})
        except httpx.TimeoutException:
            logger.info("crtsh_timeout", domain=domain)
            return PassiveDnsResult(ok=False, skipped_reason="timeout")
        except httpx.HTTPError as exc:
            raise EnrichmentError(f"crt.sh request failed: {exc}") from exc
        if r.status_code >= 400:
            raise EnrichmentError(f"crt.sh HTTP {r.status_code}: {r.text[:200]}")
        try:
            raw = r.json()
        except Exception as exc:
            raise EnrichmentError(f"crt.sh json parse failed: {exc}") from exc
        names = parse_subdomains(raw, domain)
        return PassiveDnsResult(
            ok=True,
            count=len(names),
            samples=names[: self.MAX_SAMPLES],
        )
