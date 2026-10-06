"""Daily threat brief.

Leads with what changed in the window, why it matters, and what to do next,
then backs each point with the underlying stories, vulnerabilities and
indicators. Collection problems are summarised per source at the end; raw
fetch errors stay in the Sources pages, not in the brief.

Confidence language: **Confirmed** (analyst-reviewed or CISA KEV),
**Likely** (multiple independent sources), **Possible** (single source).
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from io import StringIO

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scry.models import CVE, AnalystReview, Article, Claim, Observable, RansomwareFeedItem
from scry.reporting.common import (
    action_label,
    collection_health,
    fmt_day,
    load_watchlist_patterns,
    plural,
    rank_stories,
)

BLOCK_LEVEL = ("urgent_review", "block_if_safe")
_NON_INDICATOR_TYPES = ("cve", "attack_technique")


def generate_daily_report(session: Session, *, since_hours: int = 24) -> str:
    now = datetime.now(UTC)
    since = now - timedelta(hours=since_hours)
    window = f"last {since_hours} hours" if since_hours != 24 else "last 24 hours"

    articles = list(
        session.scalars(
            select(Article).where(Article.ingested_at >= since).order_by(Article.ingested_at.desc())
        )
    )
    watchlists = load_watchlist_patterns()
    stories, automated = rank_stories(articles, watchlists)

    new_kev = list(
        session.scalars(
            select(CVE).where(CVE.kev.is_(True), CVE.kev_added_at >= since).order_by(CVE.kev_added_at.desc())
        )
    )
    victims = list(session.scalars(select(RansomwareFeedItem).where(RansomwareFeedItem.discovered >= since)))
    block_obs = list(
        session.scalars(
            select(Observable)
            .where(
                Observable.last_seen >= since,
                Observable.actionability.in_(BLOCK_LEVEL),
                Observable.type.not_in(_NON_INDICATOR_TYPES),
            )
            .order_by(Observable.risk_score.desc())
        )
    )
    review_counts = dict(
        session.execute(
            select(AnalystReview.item_type, func.count(AnalystReview.id))
            .where(AnalystReview.status == "open")
            .group_by(AnalystReview.item_type)
        ).all()
    )
    open_reviews = sum(review_counts.values())
    enabled_sources, health = collection_health(session, since)
    feed_problem_sources = [h for h in health if h.problems]

    watch_counts: Counter[str] = Counter(w for s in stories for w in s.watchlists)
    group_counts = Counter(v.group_name for v in victims if v.group_name)
    sector_counts = Counter(v.activity for v in victims if v.activity)

    buf = StringIO()
    buf.write(f"# Scry Daily Threat Brief — {fmt_day(now)}\n\n")
    buf.write(f"_Covers the {window}, generated {now:%H:%M} UTC._\n\n")

    # ---------------- what changed ----------------
    buf.write("## What changed\n")
    changed: list[str] = []
    if new_kev:
        names = ", ".join(f"{c.cve_id} ({_product(c)})" for c in new_kev[:3])
        more = f" and {len(new_kev) - 3} more" if len(new_kev) > 3 else ""
        changed.append(
            f"CISA added {plural(len(new_kev), 'vulnerability', 'vulnerabilities')} to KEV: {names}{more}."
        )
    if victims:
        top_groups = ", ".join(f"{g} ({n})" for g, n in group_counts.most_common(3))
        line = f"{plural(len(victims), 'new ransomware leak-site post')} from {plural(len(group_counts), 'group')}"
        line += f"; most active: {top_groups}." if top_groups else "."
        changed.append(line)
    if watch_counts:
        hits = ", ".join(f"{name.replace('_', ' ')} ({n})" for name, n in watch_counts.most_common(4))
        changed.append(f"Stories matching your watchlists: {hits}.")
    if block_obs:
        changed.append(
            f"{plural(len(block_obs), 'indicator')} reached block or urgent-review level with supporting evidence."
        )
    if stories:
        changed.append(
            f"{plural(len(stories), 'distinct story', 'distinct stories')} from {plural(len(articles), 'collected article')}."
        )
    if not changed:
        changed.append("No significant changes were collected in this window.")
    for line in changed:
        buf.write(f"- {line}\n")

    # ---------------- why it matters ----------------
    buf.write("\n## Why it matters\n")
    why: list[str] = []
    if new_kev:
        why.append(
            "KEV entries are **Confirmed** exploited in the wild; exposed systems are at immediate risk."
        )
    if victims and sector_counts:
        sectors = ", ".join(s for s, _ in sector_counts.most_common(3))
        why.append(f"Ransomware posts cluster in {sectors}; check whether suppliers or peers are listed.")
    if watch_counts:
        why.append("Watchlist matches touch the technologies and threats you told Scry to monitor.")
    if block_obs:
        why.append(
            "Block-level indicators have local malicious context or vendor confirmation, not just a mention."
        )
    if not why:
        why.append("Nothing in this window requires action beyond routine monitoring.")
    for line in why:
        buf.write(f"- {line}\n")

    # ---------------- next actions ----------------
    buf.write("\n## Recommended actions\n")
    actions: list[str] = []
    if new_kev:
        actions.append(
            "Confirm exposure to and patch: "
            + ", ".join(c.cve_id for c in new_kev[:5])
            + ("…" if len(new_kev) > 5 else "")
            + "."
        )
    if block_obs:
        actions.append(
            "Review the indicators below and block those your environment does not legitimately use."
        )
    if victims:
        actions.append("Compare the ransomware victim list against your supplier and partner inventory.")
    if open_reviews:
        parts = ", ".join(f"{plural(n, t)}" for t, n in sorted(review_counts.items()))
        actions.append(f"Clear the analyst review queue ({parts}).")
    if feed_problem_sources:
        actions.append("Check the collection problems listed at the end; they leave gaps in coverage.")
    if not actions:
        actions.append("No action required.")
    for i, line in enumerate(actions, 1):
        buf.write(f"{i}. {line}\n")

    # ---------------- evidence ----------------
    buf.write("\n## Top stories\n")
    if not stories:
        buf.write("_No new articles in this window._\n")
    for story in stories[:10]:
        art = story.article
        src = art.source.name if art.source is not None else "unknown source"
        extras = []
        if story.topics:
            extras.append("topics: " + ", ".join(story.topics[:4]))
        if story.watchlists:
            extras.append("watchlist: " + ", ".join(w.replace("_", " ") for w in story.watchlists))
        if story.also_reported_by:
            extras.append("also: " + ", ".join(story.also_reported_by[:3]))
        elif story.repeats > 1:
            extras.append(f"{story.repeats} similar reports")
        tail = f" · {' · '.join(extras)}" if extras else ""
        buf.write(f"- [{story.title}]({art.url}) — {src}{tail}\n")
    if automated:
        buf.write(
            f"- _Plus {plural(automated, 'automated or imported record')} (sensor feeds, pulses, local imports), searchable in Articles._\n"
        )

    if new_kev:
        buf.write("\n## Newly added to CISA KEV\n")
        for cve in new_kev[:20]:
            flags = [
                f
                for f, on in (
                    ("ransomware use", cve.ransomware_associated),
                    ("public PoC", cve.public_poc_available),
                )
                if on
            ]
            flag_str = f" — {', '.join(flags)}" if flags else ""
            buf.write(f"- **{cve.cve_id}** {_product(cve)}{flag_str}: {_clip(cve.description, 180)}\n")

    buf.write("\n## Indicators at block or urgent-review level\n")
    if not block_obs:
        buf.write("_None in this window._\n")
    for ob in block_obs[:15]:
        buf.write(
            f"- `{ob.type}` `{ob.normalized_value}` — {action_label(ob.actionability)}, risk {ob.risk_score:.0f}"
        )
        reasons = _top_reasons(ob)
        if reasons:
            buf.write(f" ({reasons})")
        buf.write("\n")

    buf.write("\n## Analyst review queue\n")
    if not open_reviews:
        buf.write("_Nothing waiting._\n")
    else:
        for review in session.scalars(
            select(AnalystReview).where(AnalystReview.status == "open").order_by(AnalystReview.id).limit(10)
        ):
            buf.write(f"- {_review_line(session, review)}\n")
        if open_reviews > 10:
            buf.write(f"- _…and {open_reviews - 10} more on the Reviews page._\n")

    buf.write("\n## Collection health\n")
    if not health:
        buf.write(f"All {plural(enabled_sources, 'enabled source')} fetched cleanly.\n")
    else:
        clean = max(0, enabled_sources - len(feed_problem_sources))
        buf.write(f"{clean} of {plural(enabled_sources, 'enabled source')} fetched cleanly.\n")
        for h in health[:10]:
            parts = [f"{why} ({n} times)" if n > 1 else why for why, n in h.problems.most_common()]
            if h.page_failures:
                parts.append(f"{plural(h.page_failures, 'article page')} could not be fetched in full")
            line = f"- **{h.name}**: " + "; ".join(parts)
            if h.cooling_until:
                line += f" (paused until {h.cooling_until:%H:%M} UTC)"
            buf.write(line + "\n")

    buf.write("\n## How to read this brief\n")
    buf.write(
        "- **Confirmed** = analyst-reviewed or CISA KEV; **Likely** = several independent sources; "
        "**Possible** = one source.\n"
        "- Risk is how urgently to act. Indicators without local malicious context, a vendor verdict, "
        "or a second source are capped below block level.\n"
        "- Aggregator reposts do not count as independent confirmation.\n"
    )
    return buf.getvalue()


def _product(cve: CVE) -> str:
    return " ".join(p for p in (cve.vendor, cve.product) if p) or "unknown product"


def _clip(text: str | None, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def _top_reasons(ob: Observable) -> str:
    breakdown = (ob.enrichment or {}).get("risk_breakdown") or {}
    contributors = [
        c for c in breakdown.get("contributors") or [] if isinstance(c, list | tuple) and len(c) == 2
    ]
    positive = sorted(
        (c for c in contributors if c[1] > 0 and c[0] not in {"maliciousness", "source_confidence"}),
        key=lambda c: -c[1],
    )
    labels = [str(name).replace("topic:", "").replace("_", " ") for name, _ in positive[:3]]
    if "malicious-context" in (ob.tags or []):
        labels.insert(0, "malicious context in source")
    return ", ".join(labels)


def _review_line(session: Session, review: AnalystReview) -> str:
    what = ""
    if review.item_type == "claim":
        claim = session.get(Claim, review.item_id)
        if claim is not None:
            what = f"“{_clip(claim.claim_text, 120)}”"
    elif review.item_type == "observable":
        ob = session.get(Observable, review.item_id)
        if ob is not None:
            what = f"`{ob.type}` `{ob.normalized_value}`"
    claim_type = re.match(r"claim type (\S+) needs review", review.reason or "")
    if claim_type:
        reason = claim_type.group(1).replace("_", " ").capitalize() + " claim"
    else:
        reason = (review.reason or "Needs review").strip()
        reason = reason[:1].upper() + reason[1:]
    return f"{reason}: {what}" if what else reason
