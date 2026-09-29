"""RSS / Atom feed adapter."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

import feedparser
from dateutil import parser as dt_parser


@dataclass
class FeedEntry:
    title: str
    url: str
    published_at: datetime | None
    author: str | None
    summary: str | None
    content_html: str | None


def parse_feed_text(text: str) -> list[FeedEntry]:
    parsed = feedparser.parse(text)
    out: list[FeedEntry] = []
    for entry in parsed.entries:
        title = (entry.get("title") or "").strip()
        link = (entry.get("link") or "").strip()
        if not link:
            continue
        published_at = _parse_dt(entry.get("published") or entry.get("updated"))
        summary = entry.get("summary") or entry.get("description")
        author = entry.get("author")
        content_html = None
        if entry.get("content"):
            try:
                content_html = entry["content"][0].get("value")
            except Exception:
                content_html = None
        out.append(
            FeedEntry(
                title=title,
                url=link,
                published_at=published_at,
                author=author,
                summary=summary,
                content_html=content_html,
            )
        )
    return out


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = dt_parser.parse(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None


def is_feed_content_type(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(t in ct for t in ("rss", "atom", "xml"))


def iter_feed_entries(text: str) -> Iterable[FeedEntry]:
    yield from parse_feed_text(text)
