"""JSON exports."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Article, Observable


def _article_to_dict(a: Article) -> dict[str, Any]:
    return {
        "id": a.id,
        "title": a.title,
        "url": a.url,
        "source_id": a.source_id,
        "published_at": a.published_at.isoformat() if a.published_at else None,
        "ingested_at": a.ingested_at.isoformat() if a.ingested_at else None,
        "tags": a.tags,
        "summary": a.summary,
    }


def _observable_to_dict(o: Observable) -> dict[str, Any]:
    return {
        "id": o.id,
        "type": o.type,
        "normalized_value": o.normalized_value,
        "defanged_value": o.defanged_value,
        "risk_score": o.risk_score,
        "actionability": o.actionability,
        "status": o.status,
        "expiration_date": o.expiration_date.isoformat() if o.expiration_date else None,
        "tags": o.tags,
        "enrichment": o.enrichment,
        "scoring_model_version": o.scoring_model_version,
    }


def export_articles_json(session: Session, *, limit: int = 1000) -> str:
    arts = list(session.scalars(select(Article).order_by(Article.id.desc()).limit(limit)))
    return json.dumps({"articles": [_article_to_dict(a) for a in arts]}, indent=2)


def export_observables_json(session: Session, *, limit: int = 5000) -> str:
    obs = list(session.scalars(select(Observable).order_by(Observable.risk_score.desc()).limit(limit)))
    return json.dumps({"observables": [_observable_to_dict(o) for o in obs]}, indent=2)
