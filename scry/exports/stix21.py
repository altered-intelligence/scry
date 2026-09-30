"""Spec-valid STIX 2.1 export of scry intel.

Unlike ``scry.exports.stix_like`` (loose STIX-shaped JSON), this module emits
bundles that validate against the STIX 2.1 core requirements:

- bundle: ``{type: "bundle", id, objects}`` — no ``spec_version`` at bundle
  level in 2.1 (each object carries its own).
- SDOs: threat-actor, malware, campaign, intrusion-set, tool, identity,
  location, vulnerability, indicator, report, relationship, marking-definition.
- SCOs: ipv4-addr, ipv6-addr, domain-name, url, email-addr, file (hashes).
- Every object id is ``uuid5`` derived from a deterministic source string
  (``scry:<kind>:<pk>``) in a fixed scry namespace, so re-exports are stable
  and diffable.

Object-type mapping
-------------------
Entity.type        STIX SDO                      notes
---------------    ---------                     -----
threat_actor       threat-actor
malware_family     malware (is_family: true)
campaign           campaign
intrusion_set      intrusion-set
tool               tool
organization       identity (identity_class: organization)
person             identity (identity_class: individual)
sector             identity (identity_class: class)
location           location
vulnerability      vulnerability
(other)            —                             skipped

Observable.type    STIX objects
---------------    ------------
ipv4               indicator ([ipv4-addr:value = '...']) + ipv4-addr SCO
ipv6               indicator + ipv6-addr SCO
domain             indicator + domain-name SCO
url                indicator + url SCO
email              indicator + email-addr SCO
md5/sha1/...       indicator ([file:hashes.'SHA-256' = '...']) + file SCO
(other)            —                             skipped

Relationship.relationship_type is passed through with ``_`` → ``-`` (STIX
relationship types are hyphenated); anything outside ``[a-z0-9-]`` falls back
to ``related-to``.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import (
    Article,
    Entity,
    EntityMention,
    Observable,
    ObservableMention,
    Relationship,
)

# Deterministic namespace for every STIX id scry emits.
SCRY_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "scry.cti")

SPEC_VERSION = "2.1"

MARKING_DEFINITION = {
    "type": "marking-definition",
    "spec_version": SPEC_VERSION,
    "id": f"marking-definition--{uuid.uuid5(SCRY_NAMESPACE, 'scry:marking:statement')}",
    # Fixed timestamp keeps the marking (and therefore whole exports) stable.
    "created": "2024-01-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {"statement": "Unclassified scry export — verify before operational use."},
}
MARKING_ID = MARKING_DEFINITION["id"]

_ENTITY_SDO_MAP = {
    "threat_actor": "threat-actor",
    "malware_family": "malware",
    "campaign": "campaign",
    "intrusion_set": "intrusion-set",
    "tool": "tool",
    "organization": "identity",
    "person": "identity",
    "sector": "identity",
    "location": "location",
    "vulnerability": "vulnerability",
}

_IDENTITY_CLASS = {
    "organization": "organization",
    "person": "individual",
    "sector": "class",
}

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

# Observable kinds that live in the observables table (mirrors stix_like).
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

_HASH_TO_SCO_HASH = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
}

_REL_TYPE_OK = re.compile(r"^[a-z0-9-]+$")

_FALLBACK_TS = datetime(2024, 1, 1, tzinfo=UTC)


def _stix_id(stix_type: str, source: str) -> str:
    return f"{stix_type}--{uuid.uuid5(SCRY_NAMESPACE, source)}"


def _ts(value: datetime | None) -> str:
    """STIX timestamp (RFC 3339). Naive datetimes are assumed UTC."""
    if value is None:
        value = _FALLBACK_TS
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


def _escape_pattern_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _entity_sdo(ent: Entity) -> dict | None:
    stix_type = _ENTITY_SDO_MAP.get(ent.type)
    if stix_type is None:
        return None
    obj: dict = {
        "type": stix_type,
        "spec_version": SPEC_VERSION,
        "id": _stix_id(stix_type, f"scry:entity:{ent.id}"),
        "created": _ts(ent.created_at),
        "modified": _ts(ent.updated_at),
        "name": ent.canonical_name,
        "confidence": max(0, min(100, int(ent.confidence or 60))),
        "object_marking_refs": [MARKING_ID],
    }
    if ent.aliases:
        obj["aliases"] = [str(a) for a in ent.aliases]
    if ent.description:
        obj["description"] = ent.description
    if ent.tags:
        obj["labels"] = [str(t) for t in ent.tags]
    if stix_type == "malware":
        obj["is_family"] = True
    if stix_type == "identity":
        obj["identity_class"] = _IDENTITY_CLASS.get(ent.type, "unknown")
    return obj


def _observable_objects(ob: Observable) -> tuple[dict, dict | None]:
    """Indicator SDO for the observable, plus its SCO when the type maps."""
    pattern_tpl = _TYPE_TO_PATTERN.get(ob.type)
    indicator: dict = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("indicator", f"scry:observable:{ob.id}"),
        "created": _ts(ob.created_at),
        "modified": _ts(ob.updated_at),
        "name": f"{ob.type}: {ob.normalized_value}",
        "labels": [ob.type, *[str(t) for t in (ob.tags or [])]],
        "pattern_type": "stix",
        "valid_from": _ts(ob.first_reported or ob.first_seen or ob.created_at),
        "confidence": max(0, min(100, int(ob.maliciousness_confidence or 50))),
        "object_marking_refs": [MARKING_ID],
        "x_cti_risk_score": ob.risk_score,
        "x_cti_actionability": ob.actionability,
    }
    if pattern_tpl:
        indicator["pattern"] = pattern_tpl.format(v=_escape_pattern_value(ob.normalized_value))

    sco: dict | None = None
    value = ob.normalized_value
    if ob.type in ("ipv4", "ipv6", "domain", "url", "email"):
        sco_type = {
            "ipv4": "ipv4-addr",
            "ipv6": "ipv6-addr",
            "domain": "domain-name",
            "url": "url",
            "email": "email-addr",
        }[ob.type]
        sco = {
            "type": sco_type,
            "spec_version": SPEC_VERSION,
            "id": _stix_id(sco_type, f"scry:observable:{ob.id}:sco"),
            "value": value,
            "object_marking_refs": [MARKING_ID],
        }
        indicator["x_cti_sco_ref"] = sco["id"]
    elif ob.type in _HASH_TO_SCO_HASH:
        sco = {
            "type": "file",
            "spec_version": SPEC_VERSION,
            "id": _stix_id("file", f"scry:observable:{ob.id}:sco"),
            "hashes": {_HASH_TO_SCO_HASH[ob.type]: value},
            "object_marking_refs": [MARKING_ID],
        }
        indicator["x_cti_sco_ref"] = sco["id"]
    return indicator, sco


def _relationship_sdr(rel: Relationship, ent_map: dict[int, str], ob_map: dict[int, str]) -> dict | None:
    def resolve(kind: str, oid: int) -> str | None:
        if kind in _OBSERVABLE_KINDS:
            return ob_map.get(oid)
        return ent_map.get(oid)

    source_ref = resolve(rel.source_type, rel.source_id)
    target_ref = resolve(rel.target_type, rel.target_id)
    if not source_ref or not target_ref:
        return None
    rel_type = (rel.relationship_type or "").lower().replace("_", "-")
    if not _REL_TYPE_OK.match(rel_type):
        rel_type = "related-to"
    obj: dict = {
        "type": "relationship",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("relationship", f"scry:relationship:{rel.id}"),
        "created": _ts(rel.created_at),
        "modified": _ts(rel.updated_at),
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "object_marking_refs": [MARKING_ID],
    }
    if rel.evidence_text:
        obj["description"] = rel.evidence_text
    obj["confidence"] = max(0, min(100, int(rel.confidence or 60)))
    return obj


def build_intel_bundle(session: Session, limit: int | None = None) -> dict:
    """STIX 2.1 bundle of scry entities, observables (indicators + SCOs) and relationships."""
    objects: list[dict] = [MARKING_DEFINITION]
    ent_map: dict[int, str] = {}
    ob_map: dict[int, str] = {}

    ent_stmt = select(Entity).order_by(Entity.id)
    if limit is not None:
        ent_stmt = ent_stmt.limit(limit)
    for ent in session.scalars(ent_stmt):
        sdo = _entity_sdo(ent)
        if sdo is None:
            continue
        ent_map[ent.id] = sdo["id"]
        objects.append(sdo)

    ob_stmt = select(Observable).order_by(Observable.id)
    if limit is not None:
        ob_stmt = ob_stmt.limit(limit)
    for ob in session.scalars(ob_stmt):
        indicator, sco = _observable_objects(ob)
        ob_map[ob.id] = indicator["id"]
        objects.append(indicator)
        if sco is not None:
            objects.append(sco)

    rel_stmt = select(Relationship).order_by(Relationship.id)
    if limit is not None:
        rel_stmt = rel_stmt.limit(limit)
    for rel in session.scalars(rel_stmt):
        sdr = _relationship_sdr(rel, ent_map, ob_map)
        if sdr is not None:
            objects.append(sdr)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", "scry:bundle:intel"),
        "objects": objects,
    }


def _report_sdo(session: Session, art: Article) -> dict:
    """Report SDO for one article; object_refs point at the deterministic STIX
    ids of entities/observables mentioned in it (only mapped types)."""
    object_refs: list[str] = []
    seen: set[str] = set()
    for (ent_id,) in session.execute(
        select(EntityMention.entity_id)
        .where(EntityMention.article_id == art.id)
        .order_by(EntityMention.entity_id)
    ):
        ent = session.get(Entity, ent_id)
        if ent is None:
            continue
        stix_type = _ENTITY_SDO_MAP.get(ent.type)
        if stix_type is None:
            continue
        ref = _stix_id(stix_type, f"scry:entity:{ent.id}")
        if ref not in seen:
            seen.add(ref)
            object_refs.append(ref)
    for (ob_id,) in session.execute(
        select(ObservableMention.observable_id)
        .where(ObservableMention.article_id == art.id)
        .order_by(ObservableMention.observable_id)
    ):
        ob = session.get(Observable, ob_id)
        if ob is None or ob.type not in _TYPE_TO_PATTERN:
            continue
        ref = _stix_id("indicator", f"scry:observable:{ob.id}")
        if ref not in seen:
            seen.add(ref)
            object_refs.append(ref)

    created = _ts(art.created_at)
    report: dict = {
        "type": "report",
        "spec_version": SPEC_VERSION,
        "id": _stix_id("report", f"scry:article:{art.id}"),
        "created": created,
        "modified": _ts(art.updated_at),
        "name": art.title or art.url or f"scry article {art.id}",
        "published": _ts(art.published_at or art.ingested_at) or created,
        "object_refs": object_refs,
        "object_marking_refs": [MARKING_ID],
        "external_references": [
            {
                "source_name": "scry",
                "external_id": str(art.id),
                "url": art.url,
            }
        ],
    }
    if art.tags:
        report["labels"] = [str(t) for t in art.tags]
    return report


def build_articles_bundle(session: Session, limit: int | None = None) -> dict:
    """STIX 2.1 bundle of report SDOs for recent articles (newest first)."""
    objects: list[dict] = [MARKING_DEFINITION]
    stmt = select(Article).order_by(Article.id.desc())
    if limit is not None:
        stmt = stmt.limit(limit)
    for art in session.scalars(stmt):
        objects.append(_report_sdo(session, art))
    return {
        "type": "bundle",
        "id": _stix_id("bundle", "scry:bundle:articles"),
        "objects": objects,
    }
