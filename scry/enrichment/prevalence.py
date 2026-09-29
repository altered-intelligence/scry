"""Prevalence / rarity enricher.

Counts how many distinct articles + distinct sources mention each
observable; produces a rarity score where lower = rarer.
"""

from __future__ import annotations

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from scry.models import Article, Observable, ObservableMention


def prevalence_summary(session: Session, observable_id: int) -> dict:
    n_articles = (
        session.scalar(
            select(func.count(distinct(ObservableMention.article_id))).where(
                ObservableMention.observable_id == observable_id
            )
        )
        or 0
    )
    n_sources = (
        session.scalar(
            select(func.count(distinct(Article.source_id)))
            .join(ObservableMention, ObservableMention.article_id == Article.id)
            .where(ObservableMention.observable_id == observable_id)
        )
        or 0
    )
    return {
        "article_mentions": int(n_articles),
        "distinct_sources": int(n_sources),
        "rarity_score": _rarity_score(int(n_articles), int(n_sources)),
    }


def _rarity_score(articles: int, sources: int) -> float:
    if articles <= 1 and sources <= 1:
        return 90.0  # very rare = potentially high signal
    if articles <= 3:
        return 70.0
    if articles <= 10:
        return 40.0
    return 10.0


def all_observables_prevalence(session: Session) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for (ob_id,) in session.execute(select(Observable.id)):
        out[ob_id] = prevalence_summary(session, ob_id)
    return out
