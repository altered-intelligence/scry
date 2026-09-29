"""Email enricher: split user/domain, flag impersonation/lure cues."""

from __future__ import annotations

from typing import Any

from scry.enrichment.base import BaseEnricher, EnrichmentOutput
from scry.enrichment.infrastructure import InfrastructureEnricher

_LURE_HINTS = (
    "invoice",
    "payment",
    "remittance",
    "purchase order",
    "po-",
    "shipment",
    "tracking",
    "docusign",
    "office365",
    "outlook",
    "onedrive",
    "sharepoint",
    "voicemail",
    "mfa",
    "password reset",
)


class EmailEnricher(BaseEnricher):
    name = "email"
    requires_network = False

    def __init__(self) -> None:
        self.infra = InfrastructureEnricher()

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        user, _, domain = value.partition("@")
        domain = domain.lower()
        infra = self.infra.enrich(domain).fields if domain else {}
        ctx_text = ((context or {}).get("evidence_text") or "").lower()
        lures = [h for h in _LURE_HINTS if h in ctx_text]
        return EnrichmentOutput(
            fields={
                "local_part": user,
                "domain": domain,
                "lure_hints": lures,
                **infra,
            },
            rationale=[f"lure hints: {','.join(lures)}" if lures else "no lure hints detected"],
        )
