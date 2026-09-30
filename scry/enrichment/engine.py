"""Enrichment engine.

Orchestrates the registered enrichers for each observable type and writes
the result into the observable's `enrichment` JSON column.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.enrichment.abuseipdb import AbuseIPDBEnricher
from scry.enrichment.attack_mapping import AttackMappingEnricher
from scry.enrichment.email import EmailEnricher
from scry.enrichment.greynoise import GreyNoiseEnricher
from scry.enrichment.infrastructure import InfrastructureEnricher
from scry.enrichment.otx import OTXEnricher
from scry.enrichment.prevalence import prevalence_summary
from scry.enrichment.provider_settings import load_provider_states, selected_providers
from scry.enrichment.url import URLEnricher
from scry.enrichment.virustotal import VirusTotalEnricher
from scry.enrichment.vulnerability import VulnerabilityEnricher
from scry.logging import get_logger
from scry.models import Observable

logger = get_logger("enrichment")

# Observable types supported by external enrichers
_VT_TYPES = {"domain", "url", "ipv4", "ipv6", "sha256", "sha1", "md5"}
_OTX_TYPES = {"domain", "hostname", "ipv4", "ipv6", "url", "md5", "sha1", "sha256"}
_IP_TYPES = {"ipv4", "ipv6"}

# External provider registry: name → supported types + result-count key.
# The per-provider "checked" marker in observable.enrichment is
# f"{name}_checked_at" for every provider.
_EXTERNAL_PROVIDERS: dict[str, dict[str, Any]] = {
    "virustotal": {"types": _VT_TYPES, "count_key": "vt_enriched"},
    "otx": {"types": _OTX_TYPES, "count_key": "otx_enriched"},
    "abuseipdb": {"types": _IP_TYPES, "count_key": "abuseipdb_enriched"},
    "greynoise": {"types": _IP_TYPES, "count_key": "greynoise_enriched"},
}

_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_HASH_RE = re.compile(r"^[0-9a-fA-F]+$")


def _is_valid_for_external(ob_type: str, value: str) -> bool:
    """Quick sanity check before wasting API quota on obviously-invalid values."""
    if not value or len(value) > 512:
        return False
    if ob_type in {"ipv4", "ipv6"}:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    if ob_type == "domain":
        return bool(_DOMAIN_RE.match(value)) and "." in value and " " not in value
    if ob_type == "url":
        try:
            p = urlparse(value)
            return p.scheme in {"http", "https"} and bool(p.netloc) and " " not in value
        except Exception:
            return False
    if ob_type in {"sha256", "md5", "sha1"}:
        lengths = {"md5": 32, "sha1": 40, "sha256": 64}
        return len(value) == lengths.get(ob_type, 0) and bool(_HASH_RE.match(value))
    return True


@dataclass
class EnrichmentResult:
    fields: dict[str, Any]
    rationale: list[str]


class EnrichmentEngine:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.infra = InfrastructureEnricher()
        self.url = URLEnricher()
        self.email = EmailEnricher()
        self.vuln = VulnerabilityEnricher(session)
        self.attack = AttackMappingEnricher()
        # External providers: DB-stored key wins over the env fallback;
        # toggle state comes from connector_settings (default enabled).
        self.provider_states = load_provider_states(session)
        self.vt = VirusTotalEnricher(api_key=self.provider_states["virustotal"].api_key)
        self.otx = OTXEnricher(api_key=self.provider_states["otx"].api_key)
        self.abuseipdb = AbuseIPDBEnricher(api_key=self.provider_states["abuseipdb"].api_key)
        self.greynoise = GreyNoiseEnricher(api_key=self.provider_states["greynoise"].api_key)
        self._external = {
            "virustotal": self.vt,
            "otx": self.otx,
            "abuseipdb": self.abuseipdb,
            "greynoise": self.greynoise,
        }

    def enrich_observable(
        self, observable: Observable, *, evidence_text: str | None = None
    ) -> EnrichmentResult:
        ctx = {"evidence_text": evidence_text or "", "observable_type": observable.type}
        ob_type = observable.type
        value = observable.normalized_value

        merged: dict[str, Any] = dict(observable.enrichment or {})
        rationale: list[str] = []

        if ob_type in {"domain", "url"} and ob_type == "domain":
            res = self.infra.enrich(value, context=ctx)
            merged.update(res.fields)
            rationale.extend(res.rationale)
        elif ob_type == "url":
            res = self.url.enrich(value, context=ctx)
            merged.update(res.fields)
            rationale.extend(res.rationale)
        elif ob_type == "email":
            res = self.email.enrich(value, context=ctx)
            merged.update(res.fields)
            rationale.extend(res.rationale)
        elif ob_type in {"ipv4", "ipv6"}:
            merged.setdefault("address_family", ob_type)
            rationale.append("network address; enrich with passive DNS upstream when available")
        elif ob_type == "cve":
            res = self.vuln.enrich(value, context=ctx)
            merged.update(res.fields)
            rationale.extend(res.rationale)
        elif ob_type == "attack_technique":
            res = self.attack.enrich(value, context=ctx)
            merged.update(res.fields)
            rationale.extend(res.rationale)

        merged["prevalence"] = prevalence_summary(self.session, observable.id)
        rationale.append(
            f"prevalence: {merged['prevalence']['article_mentions']} articles, "
            f"{merged['prevalence']['distinct_sources']} sources"
        )

        observable.enrichment = merged
        return EnrichmentResult(fields=merged, rationale=rationale)

    def _merge_external_result(
        self,
        observable: Observable,
        merged: dict[str, Any],
        rationale: list[str],
        name: str,
    ) -> None:
        """Run one external provider on the observable and merge its output."""
        ob_type = observable.type
        value = observable.normalized_value
        enricher = self._external[name]
        res = enricher.enrich(value, context={"observable_type": ob_type})
        merged.update(res.fields)
        rationale.extend(res.rationale)
        merged[f"{name}_checked_at"] = datetime.now(UTC).isoformat()
        if res.tags:
            existing = list(observable.tags or [])
            for tag in res.tags:
                if tag not in existing:
                    existing.append(tag)
            observable.tags = existing

    def _select_external(
        self, providers: list[str] | None
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """Apply the providers filter + enable/key gating.

        Returns (runnable name→enricher, skipped name→reason). Raises
        ValueError on unknown provider names.
        """
        runnable_states, skipped = selected_providers(self.provider_states, providers)
        return (
            {name: self._external[name] for name in runnable_states},
            skipped,
        )

    def enrich_observable_external(
        self, observable: Observable, providers: list[str] | None = None
    ) -> EnrichmentResult:
        """Run external enrichment on a single observable (network calls, cached).

        `providers` optionally restricts which providers run (default: all
        configured/enabled). Disabled or keyless providers are skipped.
        """
        ob_type = observable.type
        value = observable.normalized_value

        merged: dict[str, Any] = dict(observable.enrichment or {})
        rationale: list[str] = []

        runnable, skipped = self._select_external(providers)
        for name, reason in skipped.items():
            rationale.append(f"{name} skipped: {reason}")

        for name in runnable:
            if ob_type not in _EXTERNAL_PROVIDERS[name]["types"]:
                continue
            if not _is_valid_for_external(ob_type, value):
                rationale.append(f"{name} skipped: value failed sanity check")
                continue
            try:
                self._merge_external_result(observable, merged, rationale, name)
            except Exception as exc:
                logger.warning("external_enrich_error", provider=name, exc=str(exc))
                rationale.append(f"{name} error: {exc}")

        merged["prevalence"] = prevalence_summary(self.session, observable.id)

        observable.enrichment = merged
        return EnrichmentResult(fields=merged, rationale=rationale)

    def run_external_enrichment_batch(
        self, limit: int = 200, providers: list[str] | None = None
    ) -> dict[str, Any]:
        """Enrich observables not yet checked by the selected providers.

        Returns per-provider enriched counts plus errors/skip bookkeeping.
        """
        runnable, skipped = self._select_external(providers)
        # Only observables whose type at least one selected provider supports.
        selected_types: set[str] = set()
        for name in runnable:
            selected_types |= _EXTERNAL_PROVIDERS[name]["types"]

        counts = {name: 0 for name in runnable}
        errors = 0

        all_obs = self.session.scalars(select(Observable)).all()
        to_enrich = [
            ob
            for ob in all_obs
            if ob.type in selected_types
            and _is_valid_for_external(ob.type, ob.normalized_value)
            and any(
                f"{name}_checked_at" not in (ob.enrichment or {})
                for name in runnable
                if ob.type in _EXTERNAL_PROVIDERS[name]["types"]
            )
        ][:limit]

        logger.info(
            "external_enrichment_batch_start", total=len(to_enrich), providers=sorted(runnable)
        )

        for ob in to_enrich:
            try:
                merged: dict[str, Any] = dict(ob.enrichment or {})
                rationale: list[str] = []
                for name in runnable:
                    if ob.type not in _EXTERNAL_PROVIDERS[name]["types"]:
                        continue
                    if f"{name}_checked_at" in merged:
                        continue
                    before = dict(merged)
                    self._merge_external_result(ob, merged, rationale, name)
                    if merged != before or f"{name}_checked_at" in merged:
                        counts[name] += 1

                merged["prevalence"] = prevalence_summary(self.session, ob.id)
                ob.enrichment = merged
            except Exception as exc:
                logger.warning("external_enrich_error", ob_id=ob.id, exc=str(exc))
                errors += 1

        self.session.commit()
        result: dict[str, Any] = {
            _EXTERNAL_PROVIDERS[name]["count_key"]: counts[name] for name in runnable
        }
        result.update(
            {
                "errors": errors,
                "total_candidates": len(to_enrich),
                "providers": sorted(runnable),
                "skipped": skipped,
            }
        )
        logger.info("external_enrichment_batch_done", counts=counts, errors=errors)
        return result
