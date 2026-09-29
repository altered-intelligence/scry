"""Topic classifier dispatcher.

Each topic is a list of trigger patterns. Multiple topics can fire on the
same article. Tags returned here are what downstream search, scoring,
alerting, and reporting key off of.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class TopicTag:
    tag: str
    weight: int  # 0-100 — how strongly this article matches the topic
    evidence_text: str = ""


_TOPIC_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "microsoft": [
        re.compile(
            r"(?i)\b(?:Microsoft|Windows|Exchange|SharePoint|Outlook|Office\s*365|Entra\s*ID|Azure|Defender|Active\s+Directory|Kerberos|NTLM|IIS|RDP|MSRC|Patch\s+Tuesday|SQL\s+Server)\b"
        ),
    ],
    "appdomainmanager-hijacking": [
        re.compile(r"(?i)\bAppDomainManager(?:\s+hijack)?\b"),
        re.compile(r"(?i)\.NET\s+hijack(?:ing)?\b"),
        re.compile(r"(?i)application\s+domain\s+manager"),
    ],
    "exploit-poc": [
        re.compile(
            r"(?i)\b(?:proof[- ]of[- ]concept|PoC)\b.*\b(?:released|published|posted|available|disclosed)"
        ),
        re.compile(
            r"(?i)\bmetasploit\s+module\b|\bnuclei\s+template\b|\bweaponized\s+exploit\b|\bexploit\s+chain\b"
        ),
        re.compile(r"(?i)\bgithub\.com/[^\s]+(?:poc|exploit|cve-\d{4}-\d+)", re.IGNORECASE),
    ],
    "exploited-in-the-wild": [
        re.compile(
            r"(?i)\b(?:actively\s+exploited|exploited\s+in\s+the\s+wild|in[- ]the[- ]wild\s+exploitation|zero[- ]day|cisa\s+kev)\b"
        ),
    ],
    "ransomware": [
        re.compile(
            r"(?i)\bransomware\b|\bdouble\s+extortion\b|\bleak\s+site\b|\bRaaS\b|\binitial\s+access\s+broker\b"
        ),
    ],
    "wiper": [
        re.compile(r"(?i)\bwiper\b|\bdestructive\s+malware\b|\bdisk[- ]wiping\b|\bMBR\s+overwrite\b"),
    ],
    "ai-security": [
        re.compile(
            r"(?i)\b(?:prompt\s+injection|LLM\s+jailbreak|adversarial\s+ML|model\s+poisoning|deepfake|agentic\s+AI|AI[- ]generated\s+(?:phish|malware)|LLM\s+abuse)"
        ),
    ],
    "defense-industry": [
        re.compile(
            r"(?i)\b(?:defense\s+industrial\s+base|defense\s+contractor|aerospace\s+supplier|DIB|DoD|CMMC|ITAR|military\s+supplier)\b"
        ),
    ],
    "supply-chain": [
        re.compile(
            r"(?i)\bsupply[- ]chain\s+(?:attack|compromise)\b|\bmalicious\s+(?:npm|PyPI|gem|Docker)\s+package\b|\btyposquat\b"
        ),
    ],
    "infostealer": [
        re.compile(
            r"(?i)\binfo[- ]?stealer\b|\bbrowser\s+credential\s+theft\b|\bcookie\s+theft\b|\bRedLine\b|\bLumma\b"
        ),
    ],
    "phishing": [
        re.compile(r"(?i)\bphishing\b|\bbusiness\s+email\s+compromise\b|\bBEC\b|\bcredential\s+harvest"),
    ],
    "cloud": [
        re.compile(
            r"(?i)\b(?:AWS|Azure|Entra|S3\s+bucket|OAuth\s+application|Kubernetes\s+cluster|cloud\s+identity)\b"
        ),
    ],
    "ics-ot": [
        re.compile(r"(?i)\b(?:ICS|SCADA|OT|operational\s+technology|HMI|PLC|Industroyer)\b"),
    ],
    "apt": [
        re.compile(r"(?i)\bAPT\d+\b|\bnation[- ]state\b|\bstate[- ]sponsored\b"),
    ],
}


def classify_all(text: str) -> list[TopicTag]:
    if not text:
        return []
    out: list[TopicTag] = []
    for tag, patterns in _TOPIC_PATTERNS.items():
        for patt in patterns:
            m = patt.search(text)
            if not m:
                continue
            out.append(TopicTag(tag=tag, weight=70, evidence_text=_window(text, m.start(), m.end())))
            break
    return out


def _window(text: str, start: int, end: int, *, pad: int = 80) -> str:
    return text[max(0, start - pad) : min(len(text), end + pad)].replace("\n", " ").strip()
