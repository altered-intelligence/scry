"""Dictionary-based entity extractor.

Looks up known threat actors / malware families / ransomware groups via the
aliases.yaml dictionary. We deliberately use string-match dictionaries
rather than NER because the actor/malware name landscape is small and
custom NER would hallucinate more than it catches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scry.config import load_aliases
from scry.schemas.extraction import EntityCandidate


@dataclass
class _Term:
    canonical: str
    aliases: list[str]
    entity_type: str
    attributes: dict


def _build_dictionary() -> list[_Term]:
    data = load_aliases()
    terms: list[_Term] = []

    for canonical, info in (data.get("threat_actors") or {}).items():
        info = info or {}
        terms.append(
            _Term(
                canonical=canonical.replace("_", " "),
                aliases=list(info.get("aliases", [])),
                entity_type="threat_actor",
                attributes={k: v for k, v in info.items() if k != "aliases"},
            )
        )
    for canonical, info in (data.get("malware_families") or {}).items():
        info = info or {}
        terms.append(
            _Term(
                canonical=canonical.replace("_", " "),
                aliases=list(info.get("aliases", [])),
                entity_type="malware_family",
                attributes={k: v for k, v in info.items() if k != "aliases"},
            )
        )
    return terms


def _escape_term(t: str) -> str:
    return re.escape(t).replace(r"\ ", r"[\s_-]")


class EntityExtractor:
    EXTRACTOR_VERSION = "0.1"

    def __init__(self) -> None:
        self._terms = _build_dictionary()
        # Build a single compiled pattern per term for fast scanning.
        self._compiled: list[tuple[_Term, re.Pattern[str]]] = []
        for term in self._terms:
            surfaces = [term.canonical, *term.aliases]
            patt = re.compile(
                r"\b(?:" + "|".join(_escape_term(s) for s in surfaces if s) + r")\b",
                re.IGNORECASE,
            )
            self._compiled.append((term, patt))

    def extract(self, text: str) -> list[EntityCandidate]:
        if not text:
            return []
        candidates: list[EntityCandidate] = []
        for term, patt in self._compiled:
            m = patt.search(text)
            if not m:
                continue
            candidates.append(
                EntityCandidate(
                    type=term.entity_type,
                    canonical_name=term.canonical,
                    surface_form=m.group(0),
                    aliases=list(term.aliases),
                    evidence_text=_window(text, m.start(), m.end()),
                    extraction_method="dictionary",
                    extraction_confidence=85,
                )
            )
        return candidates


def _window(text: str, start: int, end: int, *, pad: int = 80) -> str:
    return text[max(0, start - pad) : min(len(text), end + pad)].replace("\n", " ").strip()
