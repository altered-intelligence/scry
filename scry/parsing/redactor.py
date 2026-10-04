"""Secret / credential redactor.

Removes obvious secrets and credential-style strings before they hit the DB
or any search index. This is a defensive guardrail, not a replacement for
data-classification tooling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    # AWS secret keys are exactly 40 chars of base64url; require the AKIA key nearby to reduce false-positives
    (
        "aws_secret",
        re.compile(r"(?i)(?:aws_secret|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ),
    ("gh_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{30,}")),
    # OpenAI / Anthropic keys
    ("openai_key", re.compile(r"sk-(?:proj-|org-)?[A-Za-z0-9]{20,}")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.+?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    # Password/key assignments — require quote or whitespace boundary after value to reduce false-positives
    (
        "password_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret)\s*[:=]\s*['\"]([^\s'\"<>]{4,128})['\"]"
        ),
    ),
    (
        "authorization_header",
        re.compile(r"(?i)authorization\s*:\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9._\-+/=]{8,}"),
    ),
    (
        "session_cookie",
        re.compile(r"(?i)\b(?:session|sessionid|sid|jsessionid|phpsessid)\s*=\s*[A-Za-z0-9._\-+/=]{12,}"),
    ),
]


@dataclass
class RedactionReport:
    redacted_text: str
    counts: dict[str, int]


def redact_secrets(text: str) -> RedactionReport:
    if not text:
        return RedactionReport(text or "", {})
    counts: dict[str, int] = {}
    out = text
    for name, pattern in PATTERNS:

        def _sub(m: re.Match[str], name: str = name) -> str:
            counts[name] = counts.get(name, 0) + 1
            return f"[REDACTED:{name}]"

        out = pattern.sub(_sub, out)
    return RedactionReport(redacted_text=out, counts=counts)
