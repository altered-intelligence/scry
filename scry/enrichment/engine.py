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

from scry.enrichment.attack_mapping import AttackMappingEnricher
from scry.enrichment.email import EmailEnricher
from scry.enrichment.infrastructure import InfrastructureEnricher
from scry.enrichment.otx import OTXEnricher
from scry.enrichment.prevalence import prevalence_summary
from scry.enrichment.url import URLEnricher
from scry.enrichment.virustotal import VirusTotalEnricher
from scry.enrichment.vulnerability import VulnerabilityEnricher
from scry.logging import get_logger
from scry.models import Observable

logger = get_logger("enrichment")

# Observable types supported by external enrichers
_VT_TYPES = {"domain", "url", "ipv4", "ipv6", "sha256", "sha1", "md5"}
_OTX_TYPES = {"domain", "hostname", "ipv4", "ipv6", "url", "md5", "sha1", "sha256"}

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
        self.vt = VirusTotalEnricher()
        self.otx = OTXEnricher()

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

    def enrich_observable_external(self, observable: Observable) -> EnrichmentResult:
        """Run VT + OTX enrichment on a single observable (network calls, cached)."""
        ob_type = observable.type
        value = observable.normalized_value
        ctx = {"observable_type": ob_type}

        merged: dict[str, Any] = dict(observable.enrichment or {})
        rationale: list[str] = []

        if ob_type in _VT_TYPES and self.vt.api_key and _is_valid_for_external(ob_type, value):
            vt_res = self.vt.enrich(value, context=ctx)
            merged.update(vt_res.fields)
            rationale.extend(vt_res.rationale)
            merged["virustotal_checked_at"] = datetime.now(UTC).isoformat()

        if ob_type in _OTX_TYPES and self.otx.api_key and _is_valid_for_external(ob_type, value):
            otx_res = self.otx.enrich(value, context=ctx)
            merged.update(otx_res.fields)
            rationale.extend(otx_res.rationale)
            merged["otx_checked_at"] = datetime.now(UTC).isoformat()

        merged["prevalence"] = prevalence_summary(self.session, observable.id)

        observable.enrichment = merged
        return EnrichmentResult(fields=merged, rationale=rationale)

    def run_external_enrichment_batch(self, limit: int = 200) -> dict[str, int]:
        """Enrich all observables that haven't been checked by VT/OTX yet.

        Returns counts of enriched observables per provider.
        """
        vt_count = 0
        otx_count = 0
        errors = 0

        all_obs = self.session.scalars(select(Observable)).all()
        to_enrich = [
            ob
            for ob in all_obs
            if ob.type in (_VT_TYPES | _OTX_TYPES)
            and _is_valid_for_external(ob.type, ob.normalized_value)
            and (
                "virustotal_checked_at" not in (ob.enrichment or {})
                or "otx_checked_at" not in (ob.enrichment or {})
            )
        ][:limit]

        logger.info("external_enrichment_batch_start", total=len(to_enrich))

        for ob in to_enrich:
            try:
                merged: dict[str, Any] = dict(ob.enrichment or {})
                ctx = {"observable_type": ob.type}

                if ob.type in _VT_TYPES and self.vt.api_key and "virustotal_checked_at" not in merged:
                    vt_res = self.vt.enrich(ob.normalized_value, context=ctx)
                    merged.update(vt_res.fields)
                    merged["virustotal_checked_at"] = datetime.now(UTC).isoformat()
                    vt_count += 1

                if ob.type in _OTX_TYPES and self.otx.api_key and "otx_checked_at" not in merged:
                    otx_res = self.otx.enrich(ob.normalized_value, context=ctx)
                    merged.update(otx_res.fields)
                    merged["otx_checked_at"] = datetime.now(UTC).isoformat()
                    otx_count += 1

                merged["prevalence"] = prevalence_summary(self.session, ob.id)
                ob.enrichment = merged
            except Exception as exc:
                logger.warning("external_enrich_error", ob_id=ob.id, exc=str(exc))
                errors += 1

        self.session.commit()
        logger.info("external_enrichment_batch_done", vt=vt_count, otx=otx_count, errors=errors)
        return {
            "vt_enriched": vt_count,
            "otx_enriched": otx_count,
            "errors": errors,
            "total_candidates": len(to_enrich),
        }
