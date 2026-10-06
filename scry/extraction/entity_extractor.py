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


# Names that are also ordinary English words ("play the video", "a beacon of
# hope"). They only count when written with their capitalisation AND a
# threat word sits nearby. Extend with ``ambiguous_names`` in aliases.yaml.
AMBIGUOUS_NAMES = frozenset({"play", "beacon", "hive", "royal", "akira", "conti", "storm", "chaos", "medusa"})
_THREAT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:ransomware|gang|group|operators?|affiliates?|malware|strain|variant|payload|implant|c2"
    r"|cobalt\s+strike|leak\s+site|extortion|threat\s+actors?|encrypt\w*|victims?)\b"
)
_CONTEXT_PAD = 60


class EntityExtractor:
    EXTRACTOR_VERSION = "0.1"

    def __init__(self) -> None:
        self._terms = _build_dictionary()
        ambiguous = AMBIGUOUS_NAMES | {n.lower() for n in (load_aliases().get("ambiguous_names") or [])}
        # One pattern per term for the unambiguous surfaces (case-insensitive)
        # and one for word-like surfaces (case-sensitive + context check).
        self._compiled: list[tuple[_Term, re.Pattern[str] | None, re.Pattern[str] | None]] = []
        for term in self._terms:
            surfaces = [s for s in (term.canonical, *term.aliases) if s]
            plain = [s for s in surfaces if s.lower() not in ambiguous]
            risky = [s for s in surfaces if s.lower() in ambiguous]
            plain_re = (
                re.compile(r"\b(?:" + "|".join(_escape_term(s) for s in plain) + r")\b", re.IGNORECASE)
                if plain
                else None
            )
            risky_re = (
                re.compile(r"\b(?:" + "|".join(_escape_term(s) for s in risky) + r")\b") if risky else None
            )
            self._compiled.append((term, plain_re, risky_re))

    @staticmethod
    def _first_match(text: str, plain_re, risky_re) -> re.Match[str] | None:
        if plain_re is not None:
            m = plain_re.search(text)
            if m:
                return m
        if risky_re is not None:
            for m in risky_re.finditer(text):
                window = text[max(0, m.start() - _CONTEXT_PAD) : m.end() + _CONTEXT_PAD]
                if _THREAT_CONTEXT_RE.search(window):
                    return m
        return None

    def extract(self, text: str) -> list[EntityCandidate]:
        if not text:
            return []
        candidates: list[EntityCandidate] = []
        for term, plain_re, risky_re in self._compiled:
            m = self._first_match(text, plain_re, risky_re)
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
