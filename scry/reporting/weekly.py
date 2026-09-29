"""Weekly trend report."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from io import StringIO

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scry.models import CVE, Article, Entity, EntityMention, Observable


def generate_weekly_report(session: Session) -> str:
    since = datetime.now(UTC) - timedelta(days=7)
    articles = list(session.scalars(select(Article).where(Article.ingested_at >= since)))
    obs = list(session.scalars(select(Observable).where(Observable.last_seen >= since)))
    cves = list(session.scalars(select(CVE).where(CVE.updated_at >= since)))

    tag_counts: Counter[str] = Counter()
    for art in articles:
        for tag in art.tags or []:
            tag_counts[tag] += 1

    type_counts: Counter[str] = Counter(o.type for o in obs)

    # Rank actors / malware by how often they were *mentioned in this week's
    # articles*, not by mere existence in the entity table. Counting one per
    # entity row (the previous behaviour) ignored the time window entirely and
    # produced a meaningless all-ties ranking.
    actor_counts: Counter[str] = Counter()
    malware_counts: Counter[str] = Counter()
    recent_article_ids = [a.id for a in articles]
    if recent_article_ids:
        mention_rows = session.execute(
            select(Entity.type, Entity.canonical_name, func.count(EntityMention.id))
            .join(EntityMention, EntityMention.entity_id == Entity.id)
            .where(
                EntityMention.article_id.in_(recent_article_ids),
                Entity.type.in_(("threat_actor", "malware_family")),
            )
            .group_by(Entity.id)
        ).all()
        for etype, name, cnt in mention_rows:
            if etype == "threat_actor":
                actor_counts[name] += cnt
            else:
                malware_counts[name] += cnt

    buf = StringIO()
    buf.write(f"# CTI Weekly Report — week ending {datetime.now(UTC):%Y-%m-%d}\n\n")
    buf.write("## Volume\n")
    buf.write(f"- Articles: {len(articles)}\n- Observables seen: {len(obs)}\n- CVE updates: {len(cves)}\n\n")
    buf.write("## Topic trends\n")
    for tag, count in tag_counts.most_common(15):
        buf.write(f"- {tag}: {count}\n")
    buf.write("\n## Observable distribution\n")
    for kind, count in type_counts.most_common(15):
        buf.write(f"- {kind}: {count}\n")
    buf.write("\n## Tracked actors\n")
    for actor, count in actor_counts.most_common(10):
        buf.write(f"- {actor}: {count}\n")
    buf.write("\n## Tracked malware families\n")
    for fam, count in malware_counts.most_common(10):
        buf.write(f"- {fam}: {count}\n")
    buf.write("\n## Recommended priorities\n")
    buf.write(
        "- Patch any CISA KEV CVEs not already mitigated.\n"
        "- Triage Microsoft RCE vulnerabilities with exploitation flags.\n"
        "- Hunt for ransomware activity using extracted TTPs and IOCs.\n"
        "- Review analyst queue and clear conflicting attributions.\n"
    )
    return buf.getvalue()
