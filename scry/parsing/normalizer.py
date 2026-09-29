"""Text normalization helpers."""

from __future__ import annotations

import re
import unicodedata

_WHITESPACE_RE = re.compile(r"[ \t ]+")  # noqa: RUF001  (intentionally matches NO-BREAK SPACE)
_NEWLINES_RE = re.compile(r"\n{3,}")


def normalize_text(text: str) -> str:
    """Normalize Unicode, collapse whitespace, strip BOM."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("﻿", "").replace("​", "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _WHITESPACE_RE.sub(" ", text)
    text = _NEWLINES_RE.sub("\n\n", text)
    return text.strip()
