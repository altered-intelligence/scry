"""Weekly threat brief: the week's changes, trends, and priorities for next week."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from io import StringIO

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scry.models import CVE, Article, Entity, EntityMention, Observable, RansomwareFeedItem
from scry.reporting.common import (
    collection_health,
    fmt_day,
    load_watchlist_patterns,
    plural,
    rank_stories,
    topic_tags,
)


def generate_weekly_report(session: Session) -> str:
    now = datetime.now(UTC)
    since = now - timedelta(days=7)
    articles = list(session.scalars(select(Article).where(Article.ingested_at >= since)))
    watchlists = load_watchlist_patterns()
    stories, automated = rank_stories(articles, watchlists)
    new_kev = list(
        session.scalars(
            select(CVE).where(CVE.kev.is_(True), CVE.kev_added_at >= since).order_by(CVE.kev_added_at.desc())
        )
    )
    victims = list(session.scalars(select(RansomwareFeedItem).where(RansomwareFeedItem.discovered >= since)))
    block_level = (
        session.scalar(
            select(func.count(Observable.id)).where(
                Observable.last_seen >= since,
                Observable.actionability.in_(("urgent_review", "block_if_safe")),
                Observable.type.not_in(("cve", "attack_technique")),
            )
        )
        or 0
    )

    topic_counts: Counter[str] = Counter(t for a in articles for t in topic_tags(a.tags))
    watch_counts: Counter[str] = Counter(w for s in stories for w in s.watchlists)
    group_counts = Counter(v.group_name for v in victims if v.group_name)
    sector_counts = Counter(v.activity for v in victims if v.activity)

    # Actors / malware ranked by mentions in this week's articles.
    actor_counts: Counter[str] = Counter()
    malware_counts: Counter[str] = Counter()
    recent_ids = [a.id for a in articles]
    if recent_ids:
        rows = session.execute(
            select(Entity.type, Entity.canonical_name, func.count(EntityMention.id))
            .join(EntityMention, EntityMention.entity_id == Entity.id)
            .where(
                EntityMention.article_id.in_(recent_ids),
                Entity.type.in_(("threat_actor", "malware_family")),
            )
            .group_by(Entity.id)
        ).all()
        for etype, name, cnt in rows:
            (actor_counts if etype == "threat_actor" else malware_counts)[name] += cnt

    buf = StringIO()
    buf.write(f"# Scry Weekly Threat Brief — week ending {fmt_day(now)}\n\n")

    buf.write("## What changed this week\n")
    lines: list[str] = []
    if new_kev:
        lines.append(
            f"CISA added {plural(len(new_kev), 'vulnerability', 'vulnerabilities')} to KEV "
            f"({', '.join(c.cve_id for c in new_kev[:5])}{'…' if len(new_kev) > 5 else ''})."
        )
    if victims:
        top = ", ".join(f"{g} ({n})" for g, n in group_counts.most_common(3))
        sectors = ", ".join(s for s, _ in sector_counts.most_common(3))
        line = f"{plural(len(victims), 'ransomware leak-site post')}; most active groups: {top}"
        lines.append(line + (f"; most-hit sectors: {sectors}." if sectors else "."))
    if actor_counts or malware_counts:
        named = [n for n, _ in (actor_counts + malware_counts).most_common(4)]
        lines.append("Most-discussed actors and malware: " + ", ".join(named) + ".")
    if watch_counts:
        lines.append(
            "Watchlist activity: "
            + ", ".join(f"{n.replace('_', ' ')} ({c})" for n, c in watch_counts.most_common(4))
            + "."
        )
    if block_level:
        lines.append(f"{plural(block_level, 'indicator')} reached block or urgent-review level.")
    lines.append(
        f"{plural(len(stories), 'distinct story', 'distinct stories')} from {plural(len(articles), 'article')}"
        + (f" plus {plural(automated, 'automated or imported record')}." if automated else ".")
    )
    for line in lines:
        buf.write(f"- {line}\n")

    buf.write("\n## Stories that mattered\n")
    if not stories:
        buf.write("_No stories this week._\n")
    for story in stories[:8]:
        src = story.article.source.name if story.article.source is not None else "unknown source"
        also = f" (also: {', '.join(story.also_reported_by[:3])})" if story.also_reported_by else ""
        buf.write(f"- [{story.title}]({story.article.url}) — {src}{also}\n")

    buf.write("\n## Trends\n")
    if topic_counts:
        buf.write("- Topics: " + ", ".join(f"{t} ({n})" for t, n in topic_counts.most_common(8)) + "\n")
    if actor_counts:
        buf.write(
            "- Threat actors: " + ", ".join(f"{a} ({n})" for a, n in actor_counts.most_common(8)) + "\n"
        )
    if malware_counts:
        buf.write(
            "- Malware families: " + ", ".join(f"{m} ({n})" for m, n in malware_counts.most_common(8)) + "\n"
        )
    if not (topic_counts or actor_counts or malware_counts):
        buf.write("_Not enough data this week._\n")

    buf.write("\n## Priorities for next week\n")
    priorities: list[str] = []
    if new_kev:
        priorities.append("Close out this week's KEV additions on exposed systems.")
    if victims:
        priorities.append("Check this week's ransomware victims against suppliers and partners.")
    if block_level:
        priorities.append(
            "Disposition the block-level indicators so they either reach controls or are retired."
        )
    if watch_counts:
        priorities.append("Brief stakeholders on the watchlist stories above.")
    priorities.append("Keep the analyst review queue moving so corrections feed back into scoring.")
    for i, p in enumerate(priorities, 1):
        buf.write(f"{i}. {p}\n")

    enabled, health = collection_health(session, since)
    feed_problems = [h for h in health if h.problems]
    buf.write("\n## Collection health\n")
    buf.write(
        f"{max(0, enabled - len(feed_problems))} of {plural(enabled, 'enabled source')} had no feed failures this week.\n"
    )
    for h in feed_problems[:8]:
        buf.write(f"- **{h.name}**: " + ", ".join(why for why, _ in h.problems.most_common(2)) + "\n")
    return buf.getvalue()
