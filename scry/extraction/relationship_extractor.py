"""Relationship extractor.

Co-occurrence within a sentence window plus verb cues. Each relationship
candidate carries the evidence text and is marked explicit or inferred.
Conservative — only emits typed relationships when a clear cue is present.
"""

from __future__ import annotations

import re

from scry.schemas.extraction import (
    EntityCandidate,
    IOCCandidate,
    RelationshipCandidate,
)

CUES: dict[str, list[str]] = {
    "exploits": [r"\bexploit(?:s|ed|ing)?\b", r"\bweaponize(?:s|d|ing)?\b"],
    "delivers": [r"\bdeliver(?:s|ed|ing)?\b", r"\bdrop(?:s|ped|ping)?\b"],
    "uses": [r"\buses?\b", r"\bemploys?\b", r"\bleverag(?:e|es|ed|ing)\b"],
    "communicates_with": [
        r"\b(?:beacon|callback|c2|command[- ]and[- ]control|talks?\s+to|communicates?\s+with)\b"
    ],
    "targets": [r"\btarget(?:s|ed|ing)?\b", r"\bvictims?\s+include\b"],
    "attributed_to": [r"\battributed\s+to\b", r"\btracked\s+as\b"],
    "resolves_to": [r"\bresolves?\s+to\b"],
    "hosted_on": [r"\bhosted\s+on\b"],
    "downloads_from": [r"\bdownloads?\s+from\b"],
}


class RelationshipExtractor:
    EXTRACTOR_VERSION = "0.1"

    def extract(
        self,
        text: str,
        *,
        iocs: list[IOCCandidate],
        entities: list[EntityCandidate],
    ) -> list[RelationshipCandidate]:
        if not text:
            return []

        sentences = _split_sentences(text)
        out: list[RelationshipCandidate] = []

        for sentence in sentences:
            sentence_lower = sentence.lower()

            # ----- entity-to-entity using verb cues -----
            present_entities = [e for e in entities if e.surface_form.lower() in sentence_lower]
            for rel_type, cues in CUES.items():
                if not any(re.search(c, sentence_lower) for c in cues):
                    continue
                for a in present_entities:
                    for b in present_entities:
                        if a is b:
                            continue
                        if (a.type, b.type) in _allowed_entity_pairs(rel_type):
                            out.append(
                                RelationshipCandidate(
                                    source_type=a.type,
                                    source_value=a.canonical_name,
                                    target_type=b.type,
                                    target_value=b.canonical_name,
                                    relationship_type=rel_type,
                                    confidence=65,
                                    evidence_text=sentence.strip(),
                                    explicit_or_inferred="inferred",
                                    extraction_method="cooccurrence",
                                )
                            )

            # ----- entity ↔ ioc co-occurrence -----
            present_iocs = [
                i
                for i in iocs
                if i.normalized_value.lower() in sentence_lower or i.value.lower() in sentence_lower
            ]
            for entity in present_entities:
                for ioc in present_iocs:
                    rtype = _entity_ioc_relationship(entity.type, ioc.type, sentence_lower)
                    if not rtype:
                        continue
                    out.append(
                        RelationshipCandidate(
                            source_type=entity.type,
                            source_value=entity.canonical_name,
                            target_type=ioc.type,
                            target_value=ioc.normalized_value,
                            relationship_type=rtype,
                            confidence=60,
                            evidence_text=sentence.strip(),
                            explicit_or_inferred="inferred",
                            extraction_method="cooccurrence",
                        )
                    )

            # ----- ioc ↔ cve -----
            cves_in_sentence = [i for i in iocs if i.type == "cve" and i.normalized_value in sentence.upper()]
            actor_in_sentence = [e for e in present_entities if e.type == "threat_actor"]
            for actor in actor_in_sentence:
                for cve in cves_in_sentence:
                    out.append(
                        RelationshipCandidate(
                            source_type="threat_actor",
                            source_value=actor.canonical_name,
                            target_type="cve",
                            target_value=cve.normalized_value,
                            relationship_type="exploits",
                            confidence=65,
                            evidence_text=sentence.strip(),
                            explicit_or_inferred="inferred",
                            extraction_method="cooccurrence",
                        )
                    )

        return _dedupe(out)


def _allowed_entity_pairs(rel_type: str) -> set[tuple[str, str]]:
    if rel_type == "uses":
        return {("threat_actor", "malware_family"), ("threat_actor", "tool")}
    if rel_type == "attributed_to":
        return {("malware_family", "threat_actor"), ("campaign", "threat_actor")}
    if rel_type == "delivers":
        return {("malware_family", "malware_family"), ("threat_actor", "malware_family")}
    if rel_type == "exploits":
        return {("threat_actor", "malware_family"), ("malware_family", "malware_family")}
    if rel_type == "targets":
        return set()
    return set()


def _entity_ioc_relationship(entity_type: str, ioc_type: str, sentence_lower: str) -> str | None:
    if entity_type in {"threat_actor", "malware_family"}:
        if ioc_type in {"domain", "url"}:
            if (
                "c2" in sentence_lower
                or "command-and-control" in sentence_lower
                or "beacon" in sentence_lower
            ):
                return "communicates_with"
            return "associated_with"
        if ioc_type in {"ipv4", "ipv6"}:
            return "communicates_with" if "c2" in sentence_lower else "associated_with"
        if ioc_type in {"md5", "sha1", "sha256", "sha512", "ssdeep", "tlsh"}:
            return "delivers" if entity_type == "threat_actor" else "associated_with"
        if ioc_type == "cve":
            return "exploits"
        if ioc_type in {"registry_key", "named_pipe"}:
            return "uses"
        if ioc_type == "attack_technique":
            return "uses"
    return None


def _split_sentences(text: str) -> list[str]:
    raw = re.split(r"(?<=[\.!?])\s+", text)
    return [s.strip() for s in raw if s.strip()]


def _dedupe(items: list[RelationshipCandidate]) -> list[RelationshipCandidate]:
    seen: set[tuple] = set()
    out: list[RelationshipCandidate] = []
    for it in items:
        key = (it.source_type, it.source_value, it.target_type, it.target_value, it.relationship_type)
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out
