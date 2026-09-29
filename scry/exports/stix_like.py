"""STIX-like JSON bundle export.

Loose alignment with STIX 2.1 (indicator / malware / threat-actor /
relationship). Not validator-strict — intended for downstream ingestion
into STIX-aware tools that will normalize fully.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Entity, Observable, Relationship

_TYPE_TO_PATTERN = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "sha512": "[file:hashes.'SHA-512' = '{v}']",
}


def _id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def export_stix_like_bundle(session: Session, *, limit: int = 1000) -> str:
    objects: list[dict] = []
    ent_id_map: dict[int, str] = {}
    ob_id_map: dict[int, str] = {}

    for ent in session.scalars(select(Entity).limit(limit)):
        sid = _id("threat-actor" if ent.type == "threat_actor" else "malware")
        ent_id_map[ent.id] = sid
        objects.append(
            {
                "type": "threat-actor" if ent.type == "threat_actor" else "malware",
                "id": sid,
                "name": ent.canonical_name,
                "aliases": ent.aliases,
                "description": ent.description,
                "labels": [t for t in (ent.tags or [])],
                "spec_version": "2.1",
            }
        )

    for ob in session.scalars(select(Observable).limit(limit)):
        pattern = _TYPE_TO_PATTERN.get(ob.type)
        if not pattern:
            continue
        sid = _id("indicator")
        ob_id_map[ob.id] = sid
        objects.append(
            {
                "type": "indicator",
                "id": sid,
                "pattern": pattern.format(v=ob.normalized_value),
                "pattern_type": "stix",
                "valid_from": (
                    (ob.first_reported or ob.first_seen).isoformat()
                    if (ob.first_reported or ob.first_seen)
                    else None
                ),
                "labels": [ob.type, *ob.tags] if ob.tags else [ob.type],
                "x_cti_risk_score": ob.risk_score,
                "x_cti_actionability": ob.actionability,
                "spec_version": "2.1",
            }
        )

    for rel in session.scalars(select(Relationship).limit(limit)):
        src = _resolve(rel.source_type, rel.source_id, ent_id_map, ob_id_map)
        tgt = _resolve(rel.target_type, rel.target_id, ent_id_map, ob_id_map)
        if not src or not tgt:
            continue
        objects.append(
            {
                "type": "relationship",
                "id": _id("relationship"),
                "relationship_type": rel.relationship_type,
                "source_ref": src,
                "target_ref": tgt,
                "description": rel.evidence_text,
                "confidence": rel.confidence,
                "spec_version": "2.1",
            }
        )

    bundle = {
        "type": "bundle",
        "id": _id("bundle"),
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)


# IOC / observable kinds map to indicator objects; every *other* relationship
# endpoint kind (threat_actor, malware, malware_family, tool, campaign,
# intrusion_set, vulnerability, ...) is an Entity. Routing only two entity kinds
# to ent_map (the old behaviour) silently dropped or mis-resolved the rest.
_OBSERVABLE_KINDS = {
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "ssdeep",
    "tlsh",
    "registry_key",
    "named_pipe",
    "onion",
    "wallet_btc",
    "wallet_eth",
    "wallet_xmr",
    "asn",
    "telegram_handle",
    "discord_invite",
    "ip",
    "observable",
}


def _resolve(kind: str, oid: int, ent_map: dict[int, str], ob_map: dict[int, str]) -> str | None:
    if kind in _OBSERVABLE_KINDS:
        return ob_map.get(oid)
    return ent_map.get(oid)
