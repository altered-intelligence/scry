"""Defang / refang utilities.

Defanged IOCs are how analysts share indicators safely. We accept the most
common defang styles, normalize to refanged form, and also produce a
canonical defanged form to display in reports.
"""

from __future__ import annotations

import re

_REFANG_SUBS: list[tuple[re.Pattern[str], str]] = [
    # Email-style defangs first; consume surrounding spaces so "a [at] b [dot] c" -> "a@b.c".
    (re.compile(r"\s*\[at\]\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*\(at\)\s*", re.IGNORECASE), "@"),
    (re.compile(r"\s*\[@\]\s*"), "@"),
    (re.compile(r"\s*\[dot\]\s*", re.IGNORECASE), "."),
    (re.compile(r"\s*\(dot\)\s*", re.IGNORECASE), "."),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"(?<=\w) \. (?=\w)"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\bhxxp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bh\[t\]tp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bhxxps\[:\]//", re.IGNORECASE), "https://"),
    (re.compile(r"\bhxxp\[:\]//", re.IGNORECASE), "http://"),
    (
        re.compile(r"\bhttps?\[:\]//", re.IGNORECASE),
        lambda m: "https://" if m.group(0).lower().startswith("https") else "http://",
    ),
]


def refang(value: str) -> str:
    out = value
    for pat, sub in _REFANG_SUBS:
        out = pat.sub(sub, out)  # type: ignore[arg-type]
    return out


def defang(value: str) -> str:
    out = value
    out = out.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


_DEFANG_HINTS = ("[.]", "[dot]", "(dot)", "hxxp", "[:]", "[@]", "[at]", "(at)")


def looks_defanged(value: str) -> bool:
    lower = value.lower()
    return any(h in lower for h in _DEFANG_HINTS)
