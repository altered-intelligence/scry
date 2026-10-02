"""Alias / canonical-name resolution.

Resolves an arbitrary surface form to a canonical Entity, creating the
Entity row if it doesn't exist. Aliases are preserved so analysts can see
the source-specific naming.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.config import load_aliases
from scry.models import Entity


def resolve_canonical(name: str, entity_type: str) -> tuple[str, list[str]]:
    """Returns (canonical_name, aliases) using the local alias dictionary.

    Only threat actors and malware families have alias tables — other entity
    types (tool, campaign, …) pass through unchanged rather than being
    misresolved through the malware table.
    """
    aliases = load_aliases()
    if entity_type == "threat_actor":
        section = aliases.get("threat_actors", {})
    elif entity_type == "malware_family":
        section = aliases.get("malware_families", {})
    else:
        return name, []
    needle = name.lower().replace("_", " ").strip()
    for canonical, info in (section or {}).items():
        canonical_pretty = canonical.replace("_", " ")
        if needle == canonical_pretty.lower():
            return canonical_pretty, list(info.get("aliases", []))
        for alias in info.get("aliases", []):
            if needle == alias.lower():
                return canonical_pretty, list(info.get("aliases", []))
    return name, []


def upsert_entity(
    session: Session, *, surface_form: str, entity_type: str, attributes: dict | None = None
) -> Entity:
    canonical, aliases = resolve_canonical(surface_form, entity_type)
    existing = session.scalar(
        select(Entity).where(Entity.type == entity_type, Entity.canonical_name == canonical)
    )
    if existing is not None:
        # Merge attributes + aliases without losing source-specific naming.
        existing.aliases = sorted(set([*existing.aliases, *aliases, surface_form]))
        if attributes:
            merged = dict(existing.attributes or {})
            merged.update(attributes)
            existing.attributes = merged
        return existing

    entity = Entity(
        type=entity_type,
        canonical_name=canonical,
        aliases=sorted(set([*aliases, surface_form])),
        attributes=attributes or {},
    )
    session.add(entity)
    session.flush()
    return entity
