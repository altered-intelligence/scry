"""Daily report generator.

Honest about confidence: distinguishes confirmed / likely / possible.
Flags items that need analyst review and lists collection gaps (sources
that failed to fetch during the window).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from io import StringIO

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scry.models import (
    CVE,
    AnalystReview,
    Article,
    Observable,
    SourceFetch,
)


def generate_daily_report(session: Session, *, since_hours: int = 24) -> str:
    since = datetime.now(UTC) - timedelta(hours=since_hours)

    new_articles = list(
        session.scalars(
            select(Article).where(Article.ingested_at >= since).order_by(Article.ingested_at.desc())
        )
    )
    new_obs = list(
        session.scalars(
            select(Observable).where(Observable.last_seen >= since).order_by(Observable.risk_score.desc())
        )
    )
    new_kev = list(session.scalars(select(CVE).where(CVE.kev.is_(True), CVE.updated_at >= since)))
    open_reviews = (
        session.scalar(select(func.count(AnalystReview.id)).where(AnalystReview.status == "open")) or 0
    )
    failed_fetches = list(
        session.scalars(
            select(SourceFetch).where(SourceFetch.fetched_at >= since, SourceFetch.error.is_not(None))
        )
    )

    buf = StringIO()
    buf.write(f"# CTI Daily Report — {datetime.now(UTC):%Y-%m-%d %H:%M UTC}\n\n")
    buf.write(
        "> Confidence legend: **Confirmed** (analyst-reviewed or KEV), **Likely** (multiple independent sources), **Possible** (single source).\n\n"
    )

    buf.write("## Executive summary\n")
    buf.write(
        f"- Articles ingested in last {since_hours}h: **{len(new_articles)}**\n"
        f"- New / updated KEV entries: **{len(new_kev)}**\n"
        f"- New observables seen: **{len(new_obs)}**\n"
        f"- Items needing analyst review: **{open_reviews}**\n"
        f"- Source fetch failures: **{len(failed_fetches)}**\n\n"
    )

    buf.write("## Top stories\n")
    _list_articles(buf, new_articles[:10])

    buf.write("\n## Critical CVEs / KEV\n")
    if not new_kev:
        buf.write("_None in window._\n")
    for cve in new_kev[:20]:
        flags = []
        if cve.ransomware_associated:
            flags.append("ransomware")
        if cve.is_microsoft:
            flags.append("microsoft")
        if cve.public_poc_available:
            flags.append("public-poc")
        flag_str = f" ({','.join(flags)})" if flags else ""
        buf.write(
            f"- **{cve.cve_id}** {cve.vendor or ''} {cve.product or ''}{flag_str} — {cve.description or ''}\n"
        )

    buf.write("\n## High-risk observables\n")
    if not new_obs:
        buf.write("_None in window._\n")
    for ob in new_obs[:20]:
        buf.write(
            f"- `{ob.type}` `{ob.normalized_value}` — risk {ob.risk_score:.0f}, action {ob.actionability}, "
            f"tags {','.join(ob.tags or [])}\n"
        )

    buf.write("\n## Items needing analyst review\n")
    if open_reviews == 0:
        buf.write("_None open._\n")
    else:
        for review in session.scalars(select(AnalystReview).where(AnalystReview.status == "open").limit(20)):
            buf.write(
                f"- [{review.item_type} #{review.item_id}] {review.reason} (confidence {review.confidence})\n"
            )

    buf.write("\n## Collection gaps\n")
    if not failed_fetches:
        buf.write("_All configured sources fetched successfully._\n")
    else:
        for fetch in failed_fetches[:20]:
            buf.write(f"- source_id={fetch.source_id} status={fetch.status_code} error={fetch.error}\n")

    buf.write("\n## Confidence notes\n")
    buf.write(
        "- Aggregator-only reporting is not counted as independent confirmation.\n"
        "- Observables tagged `benign-shared-infrastructure` are intentionally not block-recommended.\n"
        "- IOC actionability decays per type-specific TTLs.\n"
    )
    return buf.getvalue()


def _list_articles(buf: StringIO, articles: Iterable[Article]) -> None:
    rows = list(articles)
    if not rows:
        buf.write("_No new articles in window._\n")
        return
    for art in rows:
        buf.write(f"- [{art.title or art.url}]({art.url}) — tags: {','.join(art.tags or []) or '-'}\n")
