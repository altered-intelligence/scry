"""Domain / IP enrichment.

Offline-safe enricher: parses structural attributes (TLD, eTLD+1, looks
like a dynamic DNS provider, looks like cloud / CDN, looks like a paste
site). Hooks are provided for future passive DNS / WHOIS / certificate
transparency enrichers.
"""

from __future__ import annotations

from typing import Any

import tldextract

from scry.config import load_policies
from scry.enrichment.base import BaseEnricher, EnrichmentOutput

_TLDX = tldextract.TLDExtract(suffix_list_urls=())

_CLOUD_TLDS = {
    "amazonaws.com",
    "azurewebsites.net",
    "azureedge.net",
    "core.windows.net",
    "cloudfront.net",
    "googleusercontent.com",
    "googleapis.com",
    "appspot.com",
    "azure.com",
    "cloudflare.com",
    "cloudflare.net",
    "fastly.net",
    "akamaihd.net",
    "edgekey.net",
    "edgesuite.net",
}
_DYN_DNS = {"duckdns.org", "no-ip.org", "no-ip.com", "ddns.net", "freedynamicdns.net", "dynu.net"}
_PASTE_SITES = {"pastebin.com", "paste.ee", "ghostbin.co", "0bin.net", "rentry.co", "controlc.com"}
_URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly", "is.gd"}


class InfrastructureEnricher(BaseEnricher):
    name = "infrastructure"
    requires_network = False

    def __init__(self) -> None:
        self.benign_hosts = {
            h.lower() for h in (load_policies().get("benign_infrastructure_hosts", []) or [])
        }

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        host = value.lower().rstrip(".")
        parsed = _TLDX(host)
        registered = ".".join(p for p in (parsed.domain, parsed.suffix) if p)
        fields: dict[str, Any] = {
            "tld": parsed.suffix,
            "registered_domain": registered or host,
            "subdomain": parsed.subdomain or None,
        }
        rationale: list[str] = []
        if registered in self.benign_hosts or any(host.endswith(b) for b in self.benign_hosts):
            fields["benign_shared_infrastructure"] = True
            rationale.append("matches benign_infrastructure_hosts allowlist")
        if registered in _CLOUD_TLDS or any(host.endswith(t) for t in _CLOUD_TLDS):
            fields["likely_cloud_or_cdn"] = True
            rationale.append("hosted on common cloud/CDN; treat as shared infrastructure")
        if registered in _DYN_DNS or any(host.endswith(t) for t in _DYN_DNS):
            fields["dynamic_dns"] = True
            rationale.append("dynamic DNS provider; common with commodity malware")
        if registered in _PASTE_SITES or any(host.endswith(t) for t in _PASTE_SITES):
            fields["paste_site"] = True
            rationale.append("paste site; route mention to analyst review")
        if registered in _URL_SHORTENERS or any(host.endswith(t) for t in _URL_SHORTENERS):
            fields["url_shortener"] = True
            rationale.append("URL shortener; do not block by default")
        return EnrichmentOutput(fields=fields, rationale=rationale)
