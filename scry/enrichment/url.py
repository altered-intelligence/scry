"""URL enricher: parse scheme/host/path/query, classify suspected role."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlparse

from scry.enrichment.base import BaseEnricher, EnrichmentOutput
from scry.enrichment.infrastructure import InfrastructureEnricher

_PHISHY_PATH_HINTS = (
    "/login",
    "/signin",
    "/auth",
    "/verify",
    "/account",
    "/secure",
    "/update",
    "/mfa",
    "/2fa",
)
_PAYLOAD_EXTENSIONS = (
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".lnk",
    ".scr",
    ".jar",
    ".msi",
    ".cab",
    ".chm",
    ".iso",
    ".img",
    ".one",
    ".docm",
    ".xlsm",
    ".pptm",
)


class URLEnricher(BaseEnricher):
    name = "url"
    requires_network = False

    def __init__(self) -> None:
        self.infra = InfrastructureEnricher()

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        try:
            p = urlparse(value)
        except Exception:
            return EnrichmentOutput(
                fields={"parse_error": True, "suspected_role": ["unknown"]}, rationale=["invalid url"]
            )
        host = (p.hostname or "").lower()
        infra_fields = self.infra.enrich(host).fields if host else {}
        path = p.path or "/"
        query = dict(parse_qsl(p.query, keep_blank_values=True))
        ext = ""
        if "." in path.rsplit("/", 1)[-1]:
            ext = "." + path.rsplit(".", 1)[-1].lower()

        role: list[str] = []
        if any(h in path.lower() for h in _PHISHY_PATH_HINTS):
            role.append("phishing_candidate")
        if ext in _PAYLOAD_EXTENSIONS:
            role.append("payload_delivery_candidate")
        if "redirect" in query or "url" in query or "u" in query:
            role.append("redirector_candidate")

        return EnrichmentOutput(
            fields={
                "scheme": p.scheme,
                "host": host,
                "path": path,
                "query": query,
                "file_extension": ext or None,
                "suspected_role": role or ["unknown"],
                **infra_fields,
            },
            rationale=[f"suspected role: {','.join(role) or 'unknown'}"],
        )
