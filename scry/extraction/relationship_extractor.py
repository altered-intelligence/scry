"""Relationship extractor.

Co-occurrence within a sentence window plus verb cues. Each relationship
candidate carries the evidence text and is marked explicit or inferred.
Conservative — only emits typed relationships when a clear cue is present.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Sequence

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

# Evidence for a relationship is the sentence that contains both endpoints.
# Punctuation-free inputs (pasted spreadsheets, IOC dumps) make one "sentence"
# hundreds of KB long, and that text used to be copied onto EVERY relationship
# row — 1.1 GB of a 1.3 GB real database. Evidence is therefore windowed
# around the endpoints and hard-capped. Sentences that fit the cap are stored
# verbatim, so ordinary prose is unaffected.
MAX_EVIDENCE_CHARS = 400
_EVIDENCE_PAD = 80
_ELLIPSIS = "..."
_JOINER = " ... "
_MAX_OCCURRENCES = 5000  # per endpoint — bounds work on pathological inputs

Span = tuple[int, int]


def evidence_window(
    text: str,
    endpoints: Sequence[Sequence[str]],
    *,
    max_chars: int = MAX_EVIDENCE_CHARS,
    pad: int = _EVIDENCE_PAD,
) -> str:
    """Trim ``text`` to a window that shows the relationship endpoints.

    ``endpoints`` lists, per endpoint, the surface forms it may appear as
    (an entity's aliases, an IOC's raw and normalized value, ...). Text that
    already fits in ``max_chars`` is returned verbatim (stripped). Otherwise
    the pair of occurrences closest to each other is located
    (case-insensitive), and:

    - when both fit in one window, that window is returned with up to
      ``pad`` characters of context on each side;
    - when they are too far apart, one fragment around each endpoint is
      returned, joined by an ellipsis, so both ends stay visible;
    - with only one endpoint found, the window centres on it; with none,
      the head of the text is kept.

    Cut edges carry an ellipsis marker and the result never exceeds
    ``max_chars``. Match positions come from the original text (regex,
    IGNORECASE) so case folding can never shift the slices.
    """
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    spans = [s for s in (_occurrences(text, forms) for forms in endpoints) if s]
    marker = len(_ELLIPSIS)
    if not spans:
        return _cut(text, 0, max_chars - marker)
    if len(spans) == 1:
        return _window_around(text, spans[0][0], max_chars, pad)
    a, b = _closest_pair(spans[0], spans[1])
    lo, hi = min(a[0], b[0]), max(a[1], b[1])
    if hi - lo <= max_chars - 2 * marker:
        return _window_around(text, (lo, hi), max_chars, pad)
    # Endpoints too far apart for one window: one fragment around each.
    first, second = sorted((a, b))
    half = (max_chars - 2 * marker - len(_JOINER)) // 2
    left = _fragment(text, first, half, pad)
    right = _fragment(text, second, half, pad)
    prefix = _ELLIPSIS if left[0] > 0 else ""
    suffix = _ELLIPSIS if right[1] < len(text) else ""
    return f"{prefix}{text[left[0] : left[1]].strip()}{_JOINER}{text[right[0] : right[1]].strip()}{suffix}"


def _occurrences(text: str, forms: Sequence[str]) -> list[Span]:
    """All (start, end) matches of any form, sorted by start; empty forms ignored."""
    out: list[Span] = []
    for form in forms:
        needle = (form or "").strip()
        if not needle:
            continue
        for m in re.finditer(re.escape(needle), text, flags=re.IGNORECASE):
            out.append((m.start(), m.end()))
            if len(out) >= _MAX_OCCURRENCES:
                break
    out.sort()
    return out


def _closest_pair(a_spans: list[Span], b_spans: list[Span]) -> tuple[Span, Span]:
    """The (a, b) occurrence pair covering the narrowest stretch of text."""
    b_starts = [s for s, _ in b_spans]
    best: tuple[Span, Span] | None = None
    best_width = 0
    for a in a_spans:
        i = bisect.bisect_left(b_starts, a[0])
        for j in (i - 1, i):
            if 0 <= j < len(b_spans):
                b = b_spans[j]
                width = max(a[1], b[1]) - min(a[0], b[0])
                if best is None or width < best_width:
                    best, best_width = (a, b), width
    assert best is not None  # both lists are non-empty by construction
    return best


def _fragment(text: str, span: Span, budget: int, pad: int) -> Span:
    """Bounds of a window around ``span`` that is at most ``budget`` characters."""
    start, end = span
    length = end - start
    if length >= budget:
        return start, start + budget
    extra = min(pad, (budget - length) // 2)
    return max(0, start - extra), min(len(text), end + extra)


def _window_around(text: str, span: Span, max_chars: int, pad: int) -> str:
    start, end = _fragment(text, span, max_chars - 2 * len(_ELLIPSIS), pad)
    return _cut(text, start, end)


def _cut(text: str, start: int, end: int) -> str:
    """``text[start:end]`` (stripped) with an ellipsis on each side that was cut."""
    start = max(0, start)
    end = min(len(text), end)
    piece = text[start:end].strip()
    return f"{_ELLIPSIS if start > 0 else ''}{piece}{_ELLIPSIS if end < len(text) else ''}"


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
                                    evidence_text=evidence_window(
                                        sentence, [[a.surface_form], [b.surface_form]]
                                    ),
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
                            evidence_text=evidence_window(
                                sentence, [[entity.surface_form], [ioc.value, ioc.normalized_value]]
                            ),
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
                            evidence_text=evidence_window(
                                sentence, [[actor.surface_form], [cve.normalized_value]]
                            ),
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
