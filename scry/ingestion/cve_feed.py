"""CISA KEV (and similar) JSON feed adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    short_description: str
    date_added: str | None
    ransomware_associated: bool


def parse_kev_json(text: str) -> list[KevEntry]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []
    out = []
    for raw in entries:
        if not isinstance(raw, dict):
            continue
        out.append(
            KevEntry(
                cve_id=str(raw.get("cveID", "")),
                vendor=str(raw.get("vendorProject", "")),
                product=str(raw.get("product", "")),
                short_description=str(raw.get("shortDescription", "")),
                date_added=raw.get("dateAdded"),
                ransomware_associated=str(raw.get("knownRansomwareCampaignUse", "")).lower() == "known",
            )
        )
    return out
