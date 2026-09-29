"""Claim extractor.

Pattern-based for the MVP: looks for sentences that match known claim
shapes (exploitation, attribution, victim naming, PoC release, wiper
deployment, AI-enabled, AppDomainManager abuse, etc.). Each claim carries
evidence text and is marked explicit_or_inferred so analysts can audit it.
"""

from __future__ import annotations

import re

from scry.schemas.extraction import ClaimCandidate

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "exploited_in_the_wild",
        re.compile(
            r"(?i)(?:actively\s+exploited|exploited\s+in\s+the\s+wild|exploit(?:ation)?\s+(?:has\s+been|is)\s+observed|in[- ]the[- ]wild\s+exploitation|zero[- ]day)",
            re.IGNORECASE,
        ),
        "explicit",
    ),
    (
        "attribution",
        re.compile(
            r"(?i)\battributed\s+to\b|\battribute(?:s)?\s+(?:this|the)\s+activity\s+to\b|\b(?:tracked|tracked\s+as|known\s+as)\s+[A-Z][A-Za-z0-9_]+\b"
        ),
        "explicit",
    ),
    (
        "victim_claimed",
        re.compile(
            r"(?i)\b(?:claimed\s+responsibility|listed\s+on\s+(?:the|its)\s+leak\s+site|posted\s+(?:to|on)\s+(?:their|its)\s+leak\s+site|added\s+(?:.+?)\s+to\s+(?:their|its)\s+leak\s+site)"
        ),
        "explicit",
    ),
    (
        "public_poc_released",
        re.compile(
            r"(?i)\b(?:proof[- ]of[- ]concept|PoC)\b.*\b(?:released|published|posted|available|disclosed)\b"
        ),
        "explicit",
    ),
    (
        "ransomware_deployment",
        re.compile(
            r"(?i)\bdeployed\s+(?:the\s+)?ransomware\b"
            r"|\bransomware\s+(?:was|is|has\s+been|got)\s+deployed\b"
            r"|\bencrypt(?:ed|ing)\b.*\b(?:systems|files|environment)\b"
        ),
        "explicit",
    ),
    (
        "wiper_deployment",
        re.compile(r"(?i)\b(?:wiper|destructive\s+malware|disk[- ]wiping)\b.*\b(?:deployed|observed|used)\b"),
        "explicit",
    ),
    (
        "appdomainmanager_hijacking",
        re.compile(
            r"(?i)\bAppDomainManager\s+hijack|\.NET\s+hijack(?:ing)?|application\s+domain\s+manager\s+abuse"
        ),
        "explicit",
    ),
    (
        "ai_enabled_attack",
        re.compile(
            r"(?i)\b(?:AI[- ]enabled|LLM[- ]based|prompt\s+injection|deepfake|AI[- ]generated\s+(?:phish|malware|content))"
        ),
        "explicit",
    ),
    (
        "supply_chain_compromise",
        re.compile(
            r"(?i)\bsupply[- ]chain\s+(?:attack|compromise)|\bmalicious\s+(?:npm|PyPI|gem|crate|Docker)\b"
        ),
        "explicit",
    ),
    (
        "targets_defense_industry",
        re.compile(r"(?i)\b(?:defense\s+industrial\s+base|defense\s+contractor|aerospace\s+supplier|DIB)\b"),
        "explicit",
    ),
    (
        "microsoft_vuln",
        re.compile(
            r"(?i)\bMicrosoft\b.*\b(?:vulnerability|advisory|patch\s+tuesday|RCE|remote\s+code\s+execution|elevation\s+of\s+privilege)"
        ),
        "explicit",
    ),
]


class ClaimExtractor:
    EXTRACTOR_VERSION = "0.1"

    def extract(self, text: str) -> list[ClaimCandidate]:
        if not text:
            return []
        out: list[ClaimCandidate] = []
        for claim_type, patt, evi_kind in _PATTERNS:
            for m in patt.finditer(text):
                sentence = _sentence_of(text, m.start(), m.end())
                out.append(
                    ClaimCandidate(
                        claim_text=sentence,
                        claim_type=claim_type,
                        evidence_text=sentence,
                        confidence=70,
                        explicit_or_inferred=evi_kind,
                        extraction_method="regex",
                    )
                )
        # Dedup by (claim_type, claim_text)
        seen: set[tuple[str, str]] = set()
        unique: list[ClaimCandidate] = []
        for c in out:
            key = (c.claim_type, c.claim_text[:200])
            if key in seen:
                continue
            seen.add(key)
            unique.append(c)
        return unique


def _sentence_of(text: str, start: int, end: int) -> str:
    left = text.rfind(".", 0, start)
    right = text.find(".", end)
    left = 0 if left == -1 else left + 1
    right = len(text) if right == -1 else right + 1
    return text[left:right].strip().replace("\n", " ")
