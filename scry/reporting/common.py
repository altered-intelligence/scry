"""Building blocks shared by the daily and weekly briefs.

The briefs answer three questions in order: what changed, why it matters,
and what to do next. These helpers rank and de-duplicate stories, match the
configured watchlists (the organisation's monitoring priorities), and turn
raw fetch errors into a short per-source collection-health summary.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.config import load_watchlists
from scry.extraction.classifiers.dispatch import TOPIC_TAGS
from scry.models import Article, Source, SourceFetch
from scry.scoring.risk import ACTION_LABELS

# Topics that make a story more decision-relevant, with their ranking weight.
PRIORITY_TOPICS: dict[str, int] = {
    "exploited-in-the-wild": 25,
    "ransomware": 15,
    "wiper": 15,
    "supply-chain": 12,
    "exploit-poc": 10,
    "apt": 8,
    "microsoft": 6,
    "infostealer": 6,
    "phishing": 4,
}
# Machine-generated feeds (sensor/pulse dumps) and locally imported documents
# are counted, not ranked as news stories.
AUTOMATED_SOURCE_TYPES = frozenset({"otx_pulse", "local_file"})
_NOISE_WORDS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d+(?:\.\d+){1,3}\b|[^a-z0-9 ]")


def action_label(action: str | None) -> str:
    return ACTION_LABELS.get(action or "", (action or "unknown").replace("_", " ").capitalize())


def article_title(article: Article) -> str:
    title = (article.title or "").strip()
    if title and title != "(no title)":
        return title
    host = urlsplit(article.url or "").hostname or "unknown site"
    return f"Untitled article ({host})"


def topic_tags(tags: Iterable[str]) -> list[str]:
    """Classifier topics only; provenance tags (source:x, news, aggregator) are dropped."""
    return sorted({t for t in tags or [] if t in TOPIC_TAGS})


_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "into",
        "is",
        "it",
        "its",
        "new",
        "of",
        "on",
        "or",
        "over",
        "says",
        "the",
        "their",
        "to",
        "with",
        "after",
        "amid",
        "via",
        "this",
        "that",
        "was",
        "were",
        "will",
        "reportedly",
        "report",
        "reports",
    ]
)
SAME_STORY_OVERLAP = 0.6  # shared significant title words / words in the shorter title
SAME_STORY_MIN_SHARED = 3


def title_words(title: str) -> set[str]:
    return {w for w in story_key(title).split() if len(w) > 2 and w not in _STOPWORDS}


def same_story(a: set[str], b: set[str]) -> bool:
    shared = len(a & b)
    return shared >= SAME_STORY_MIN_SHARED and shared / max(1, min(len(a), len(b))) >= SAME_STORY_OVERLAP


def story_key(title: str) -> str:
    """Normalised title used to collapse repeats ("Live Feed — 2026-10-04" twice)."""
    return " ".join(_NOISE_WORDS_RE.sub(" ", title.lower()).split())


@dataclass
class Watchlist:
    name: str
    description: str
    patterns: list[re.Pattern[str]]


def load_watchlist_patterns() -> list[Watchlist]:
    out: list[Watchlist] = []
    for wl in load_watchlists():
        words = [str(k) for k in wl.get("keywords") or [] if k]
        if not words:
            continue
        out.append(
            Watchlist(
                name=str(wl.get("name", "watchlist")),
                description=str(wl.get("description", "")),
                patterns=[re.compile(rf"(?i)\b{re.escape(w)}\b") for w in words],
            )
        )
    return out


def watchlist_hits(article: Article, watchlists: Sequence[Watchlist]) -> list[str]:
    text = f"{article.title or ''}\n{(article.extracted_text or '')[:5000]}"
    return [wl.name for wl in watchlists if any(p.search(text) for p in wl.patterns)]


@dataclass
class RankedStory:
    article: Article
    title: str
    score: float
    topics: list[str]
    watchlists: list[str]
    repeats: int = 1  # how many window articles collapsed into this story
    also_reported_by: list[str] = field(default_factory=list)


def rank_stories(
    articles: Sequence[Article], watchlists: Sequence[Watchlist]
) -> tuple[list[RankedStory], int]:
    """De-duplicated news stories, most decision-relevant first, plus the automated-record count."""
    automated = 0
    by_key: dict[str, RankedStory] = {}
    for art in articles:
        source = art.source
        if source is not None and source.type in AUTOMATED_SOURCE_TYPES:
            automated += 1
            continue
        if source is not None and art.url in {source.url, source.feed}:
            continue  # the feed/blog index page itself, not a story
        title = article_title(art)
        topics = topic_tags(art.tags)
        hits = watchlist_hits(art, watchlists)
        score = float(art.source_confidence or 50)
        score += sum(PRIORITY_TOPICS.get(t, 0) for t in topics)
        score += 20 if hits else 0
        if re.search(r"(?i)\bCVE-\d{4}-\d{4,7}\b", art.extracted_text or ""):
            score += 5
        key = story_key(title) or f"id:{art.id}"
        current = by_key.get(key)
        if current is None:
            by_key[key] = RankedStory(art, title, score, topics, hits)
        else:
            current.repeats += 1
            current.topics = sorted({*current.topics, *topics})
            current.watchlists = sorted({*current.watchlists, *hits})
            if score > current.score:
                current.article, current.title, current.score = art, title, score
    # Different outlets covering the same event: merge by title overlap,
    # keeping the highest-ranked version as the headline.
    ranked: list[RankedStory] = []
    kept_words: list[set[str]] = []
    for story in sorted(by_key.values(), key=lambda s: (-s.score, -(s.article.id or 0))):
        words = title_words(story.title)
        for kept, kept_w in zip(ranked, kept_words, strict=True):
            if same_story(words, kept_w):
                kept.repeats += story.repeats
                kept.topics = sorted({*kept.topics, *story.topics})
                kept.watchlists = sorted({*kept.watchlists, *story.watchlists})
                name = story.article.source.name if story.article.source is not None else None
                if name and name not in kept.also_reported_by:
                    kept.also_reported_by.append(name)
                break
        else:
            ranked.append(story)
            kept_words.append(words)
    return ranked, automated


@dataclass
class SourceHealth:
    name: str
    problems: Counter[str] = field(default_factory=Counter)
    page_failures: int = 0
    page_hosts: Counter[str] = field(default_factory=Counter)
    cooling_until: datetime | None = None


def describe_fetch_error(status: int | None, error: str | None) -> str:
    err = (error or "").lower()
    if status == 429 or "429" in err:
        return "rate limited (HTTP 429)"
    if status == 503:
        return "service unavailable (HTTP 503)"
    if status in (401, 403):
        return f"access denied (HTTP {status})"
    if status == 404:
        return "not found (HTTP 404)"
    if "too short" in err:
        return "empty or blocked page"
    if "timeout" in err or "timed out" in err:
        return "timed out"
    if status and status >= 500:
        return f"server error (HTTP {status})"
    if status is None:
        return "connection failed"
    return f"HTTP {status}"


def collection_health(session: Session, since: datetime) -> tuple[int, list[SourceHealth]]:
    """(enabled source count, sources with problems) for the window.

    Feed-level failures and full-article page failures are separated: one
    feed failing is a coverage gap; individual article pages failing is a
    parsing/coverage detail.
    """
    from scry.ingestion.ingest_engine import IngestionEngine

    sources = {s.id: s for s in session.scalars(select(Source)).all()}
    enabled = [s for s in sources.values() if s.enabled]
    rows = session.scalars(
        select(SourceFetch).where(SourceFetch.fetched_at >= since, SourceFetch.error.is_not(None))
    ).all()
    health: dict[int, SourceHealth] = defaultdict(lambda: SourceHealth(name=""))
    for f in rows:
        src = sources.get(f.source_id)
        if src is None:
            continue
        h = health[f.source_id]
        h.name = src.name
        if f.url in {src.feed, src.url}:
            h.problems[describe_fetch_error(f.status_code, f.error)] += 1
        else:
            h.page_failures += 1
            h.page_hosts[urlsplit(f.url).hostname or "?"] += 1
    engine = IngestionEngine(session)
    for sid, h in health.items():
        h.cooling_until = engine.throttled_until(sources[sid])
    ordered = sorted(health.values(), key=lambda h: (-sum(h.problems.values()), -h.page_failures, h.name))
    return len(enabled), ordered


def fmt_day(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(UTC)
    return f"{dt:%A %-d %B %Y}"


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"
