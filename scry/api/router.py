"""Aggregate API router.

All endpoints are mounted here. Mountpoints follow the spec:
/sources, /ingest, /articles, /observables, /entities, /claims,
/relationships, /cves, /threat-actors, /malware, /campaigns, /search,
/alerts, /watchlists, /pirs, /clusters, /reviews, /conflicts, /stats,
/trending, /reports, /exports, /health, /jobs.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scry.alerting import AlertEngine
from scry.api.deps import get_session
from scry.audit import record as audit_record
from scry.clustering import cluster_articles
from scry.config import load_pirs, load_watchlists
from scry.conflicts import detect_conflicts
from scry.enrichment import EnrichmentEngine
from scry.exports import (
    export_articles_json,
    export_observables_csv,
    export_observables_json,
    export_stix_like_bundle,
)
from scry.ingestion import IngestionEngine
from scry.models import (
    CVE,
    Alert,
    AnalystReview,
    Article,
    Campaign,
    Claim,
    Cluster,
    Conflict,
    Entity,
    Job,
    MalwareFamily,
    Observable,
    Relationship,
    Source,
    SourceFetch,
    ThreatActor,
)
from scry.models.ransomware_feed import RansomwareFeedItem
from scry.models.threat_feed import ThreatFeedItem
from scry.pipeline import CTIPipeline
from scry.reporting import generate_daily_report, generate_weekly_report
from scry.review import ReviewQueue
from scry.schemas import (
    ArticleOut,
    ArticleSummary,
    ClaimOut,
    EntityOut,
    ObservableOut,
    RelationshipOut,
    ReviewItemOut,
    ReviewUpdate,
    SearchHit,
    SemanticQuery,
    SourceIn,
    SourceOut,
)
from scry.scoring.lifecycle import LifecycleEngine
from scry.search import full_text_search, semantic_search

api_router = APIRouter()


# ---------- Health ----------


@api_router.get("/health")
def health() -> dict:
    return {"status": "ok"}


# ---------- Sources ----------


@api_router.get("/sources", response_model=list[SourceOut])
def list_sources(session: Session = Depends(get_session)):
    return session.scalars(select(Source).order_by(Source.name)).all()


@api_router.post("/sources", response_model=SourceOut)
def create_source(payload: SourceIn, session: Session = Depends(get_session)):
    if session.scalar(select(Source).where(Source.name == payload.name)):
        raise HTTPException(409, detail="Source name already exists")
    src = Source(**payload.model_dump())
    session.add(src)
    session.commit()
    audit_record(
        session, action="source.create", target_type="source", target_id=src.id, detail={"name": src.name}
    )
    return src


@api_router.get("/sources/{source_id}", response_model=SourceOut)
def get_source(source_id: int, session: Session = Depends(get_session)):
    src = session.get(Source, source_id)
    if not src:
        raise HTTPException(404)
    return src


@api_router.patch("/sources/{source_id}", response_model=SourceOut)
def patch_source(source_id: int, payload: dict, session: Session = Depends(get_session)):
    src = session.get(Source, source_id)
    if not src:
        raise HTTPException(404)
    for k, v in payload.items():
        if hasattr(src, k):
            setattr(src, k, v)
    session.commit()
    return src


@api_router.get("/sources/{source_id}/reliability")
def get_reliability(source_id: int, session: Session = Depends(get_session)):
    from scry.scoring import SourceReliabilityScorer

    src = session.get(Source, source_id)
    if not src:
        raise HTTPException(404)
    return {"source_id": source_id, "score": SourceReliabilityScorer(session).score(source_id)}


# ---------- Ingest ----------


@api_router.post("/ingest/url")
async def ingest_url(payload: dict, session: Session = Depends(get_session)):
    url = payload.get("url")
    if not url:
        raise HTTPException(422, detail="url required")
    engine = IngestionEngine(session)
    article = await engine.ingest_url(url, source_id=payload.get("source_id"))
    if not article:
        return {"status": "blocked"}
    CTIPipeline(session).process_article(article)
    return {"status": "ok", "article_id": article.id}


@api_router.post("/ingest/source/{source_id}")
async def ingest_source(source_id: int, session: Session = Depends(get_session)):
    src = session.get(Source, source_id)
    if not src:
        raise HTTPException(404)
    engine = IngestionEngine(session)
    res = await engine.ingest_source(src)
    # Process newly-ingested articles
    pipeline = CTIPipeline(session)
    for art in session.scalars(
        select(Article).where(Article.source_id == src.id, Article.extractor_version == "0")
    ):
        pipeline.process_article(art)
    return res


@api_router.post("/ingest/run")
async def ingest_run(session: Session = Depends(get_session)):
    engine = IngestionEngine(session)
    res = await engine.ingest_all()
    pipeline = CTIPipeline(session)
    for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
        pipeline.process_article(art)
    return res


@api_router.post("/enrichment/run")
def enrichment_run(session: Session = Depends(get_session), limit: int = Query(200, ge=1, le=2000)):
    """Run VT + OTX external enrichment on observables not yet checked (cached, rate-limited)."""
    engine = EnrichmentEngine(session)
    result = engine.run_external_enrichment_batch(limit=limit)
    return result


@api_router.post("/ingest/fetch-full")
async def ingest_fetch_full(session: Session = Depends(get_session), limit: int = Query(50, ge=1, le=200)):
    """Second-pass: fetch full article HTML for RSS-only stubs, re-run IOC extraction."""
    engine = IngestionEngine(session)
    fetch_res = await engine.fetch_full_content(limit=limit)
    # Re-run pipeline on newly-enriched articles
    pipeline = CTIPipeline(session)
    pipeline_count = 0
    for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
        pipeline.process_article(art)
        pipeline_count += 1
    return {**fetch_res, "pipeline_reprocessed": pipeline_count}


# ---------- Jobs ----------


@api_router.get("/jobs")
def list_jobs(session: Session = Depends(get_session), limit: int = 50):
    return [
        {
            "id": j.id,
            "kind": j.kind,
            "status": j.status,
            "started_at": j.started_at,
            "finished_at": j.finished_at,
            "error": j.error,
        }
        for j in session.scalars(select(Job).order_by(Job.id.desc()).limit(limit))
    ]


# ---------- Articles ----------


@api_router.get("/articles", response_model=list[ArticleSummary])
def list_articles(
    session: Session = Depends(get_session),
    limit: int = Query(50, ge=1, le=500),
    offset: int = 0,
    tag: str | None = None,
):
    stmt = select(Article).order_by(Article.id.desc())
    if tag:
        # JSON column contains
        stmt = stmt.where(Article.tags.contains([tag]))
    rows = session.scalars(stmt.limit(limit).offset(offset)).all()
    return rows


@api_router.get("/articles/{article_id}", response_model=ArticleOut)
def get_article(article_id: int, session: Session = Depends(get_session)):
    art = session.get(Article, article_id)
    if not art:
        raise HTTPException(404)
    return art


# ---------- Observables ----------


@api_router.get("/observables", response_model=list[ObservableOut])
def list_observables(
    session: Session = Depends(get_session),
    type: str | None = None,
    min_risk: float | None = None,
    tag: str | None = None,
    status: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = 0,
):
    stmt = select(Observable).order_by(Observable.risk_score.desc(), Observable.id.desc())
    if type:
        stmt = stmt.where(Observable.type == type)
    if min_risk is not None:
        stmt = stmt.where(Observable.risk_score >= min_risk)
    if tag:
        stmt = stmt.where(Observable.tags.contains([tag]))
    if status:
        stmt = stmt.where(Observable.status == status)
    return list(session.scalars(stmt.limit(limit).offset(offset)))


@api_router.get("/observables/search", response_model=list[ObservableOut])
def search_observables(q: str, session: Session = Depends(get_session), limit: int = 50):
    needle = f"%{q.lower()}%"
    return list(
        session.scalars(select(Observable).where(Observable.normalized_value.ilike(needle)).limit(limit))
    )


@api_router.get("/observables/{ob_id}", response_model=ObservableOut)
def get_observable(ob_id: int, session: Session = Depends(get_session)):
    ob = session.get(Observable, ob_id)
    if not ob:
        raise HTTPException(404)
    return ob


# ---------- Entities ----------


@api_router.get("/entities", response_model=list[EntityOut])
def list_entities(type: str | None = None, session: Session = Depends(get_session)):
    stmt = select(Entity)
    if type:
        stmt = stmt.where(Entity.type == type)
    return list(session.scalars(stmt))


@api_router.get("/entities/{entity_id}", response_model=EntityOut)
def get_entity(entity_id: int, session: Session = Depends(get_session)):
    e = session.get(Entity, entity_id)
    if not e:
        raise HTTPException(404)
    return e


# ---------- Claims ----------


@api_router.get("/claims", response_model=list[ClaimOut])
def list_claims(claim_type: str | None = None, session: Session = Depends(get_session), limit: int = 100):
    stmt = select(Claim).order_by(Claim.id.desc())
    if claim_type:
        stmt = stmt.where(Claim.claim_type == claim_type)
    return list(session.scalars(stmt.limit(limit)))


@api_router.get("/claims/{claim_id}", response_model=ClaimOut)
def get_claim(claim_id: int, session: Session = Depends(get_session)):
    c = session.get(Claim, claim_id)
    if not c:
        raise HTTPException(404)
    return c


# ---------- Relationships ----------


@api_router.get("/relationships", response_model=list[RelationshipOut])
def list_relationships(session: Session = Depends(get_session), limit: int = 100):
    return list(session.scalars(select(Relationship).order_by(Relationship.id.desc()).limit(limit)))


# ---------- CVEs / actors / malware / campaigns ----------


@api_router.get("/cves")
def list_cves(session: Session = Depends(get_session), only_kev: bool = False, limit: int = 100):
    stmt = select(CVE).order_by(CVE.updated_at.desc()).limit(limit)
    if only_kev:
        stmt = stmt.where(CVE.kev.is_(True))
    return [
        {
            "cve_id": c.cve_id,
            "vendor": c.vendor,
            "product": c.product,
            "severity": c.severity,
            "kev": c.kev,
            "exploited_in_the_wild": c.exploited_in_the_wild,
            "ransomware_associated": c.ransomware_associated,
            "is_microsoft": c.is_microsoft,
        }
        for c in session.scalars(stmt)
    ]


@api_router.get("/cves/{cve_id}")
def get_cve(cve_id: str, session: Session = Depends(get_session)):
    c = session.scalar(select(CVE).where(CVE.cve_id == cve_id.upper()))
    if not c:
        raise HTTPException(404)
    return {col.name: getattr(c, col.name) for col in c.__table__.columns}


@api_router.get("/threat-actors")
def list_threat_actors(session: Session = Depends(get_session)):
    return [
        {"id": t.id, "canonical_name": t.canonical_name, "aliases": t.aliases}
        for t in session.scalars(select(ThreatActor))
    ]


@api_router.get("/malware")
def list_malware(session: Session = Depends(get_session)):
    return [
        {"id": m.id, "canonical_name": m.canonical_name, "type": m.malware_type, "aliases": m.aliases}
        for m in session.scalars(select(MalwareFamily))
    ]


@api_router.get("/campaigns")
def list_campaigns(session: Session = Depends(get_session)):
    return [{"id": c.id, "name": c.name, "objective": c.objective} for c in session.scalars(select(Campaign))]


# ---------- Search ----------


@api_router.get("/search", response_model=list[SearchHit])
def search(q: str, session: Session = Depends(get_session), limit: int = 50):
    return full_text_search(session, q, limit=limit)


@api_router.post("/search/semantic", response_model=list[SearchHit])
def semantic(query: SemanticQuery, session: Session = Depends(get_session)):
    return semantic_search(session, query.q, target=query.target, limit=query.limit)


# ---------- Alerts / watchlists / PIRs / clusters / reviews / conflicts ----------


@api_router.get("/alerts")
def list_alerts(session: Session = Depends(get_session), limit: int = 100):
    return [
        {
            "id": a.id,
            "trigger": a.trigger,
            "title": a.title,
            "severity": a.severity,
            "confidence": a.confidence,
            "delivered": a.delivered,
            "created_at": a.created_at,
        }
        for a in session.scalars(select(Alert).order_by(Alert.id.desc()).limit(limit))
    ]


@api_router.post("/alerts/run")
def run_alerts(session: Session = Depends(get_session)):
    created = AlertEngine(session).evaluate()
    return {"created": len(created)}


@api_router.get("/watchlists")
def watchlists():
    return {"watchlists": load_watchlists()}


@api_router.get("/pirs")
def pirs():
    return {"pirs": load_pirs()}


@api_router.get("/clusters")
def list_clusters(session: Session = Depends(get_session), limit: int = 100):
    return [
        {"id": c.id, "kind": c.kind, "method": c.method, "members": c.members, "description": c.description}
        for c in session.scalars(select(Cluster).order_by(Cluster.id.desc()).limit(limit))
    ]


@api_router.post("/clusters/run")
def run_clusters(session: Session = Depends(get_session)):
    new = cluster_articles(session)
    return {"created": len(new)}


@api_router.get("/reviews", response_model=list[ReviewItemOut])
def list_reviews(session: Session = Depends(get_session), limit: int = 100, offset: int = 0):
    return ReviewQueue(session).list_open(limit=limit, offset=offset)


@api_router.patch("/reviews/{review_id}", response_model=ReviewItemOut)
def patch_review(review_id: int, payload: ReviewUpdate, session: Session = Depends(get_session)):
    row = ReviewQueue(session).update(
        review_id,
        status=payload.status,
        disposition=payload.disposition,
        analyst=payload.analyst,
        comments=payload.comments,
        correction=payload.correction,
    )
    if not row:
        raise HTTPException(404)
    return row


@api_router.get("/conflicts")
def list_conflicts(session: Session = Depends(get_session), limit: int = 100):
    return [
        {
            "id": c.id,
            "claim_a_id": c.claim_a_id,
            "claim_b_id": c.claim_b_id,
            "conflict_type": c.conflict_type,
            "status": c.status,
        }
        for c in session.scalars(select(Conflict).order_by(Conflict.id.desc()).limit(limit))
    ]


@api_router.post("/conflicts/run")
def run_conflicts(session: Session = Depends(get_session)):
    new = detect_conflicts(session)
    return {"created": len(new)}


# ---------- Stats / trending / reports / exports ----------


@api_router.get("/stats")
def stats(session: Session = Depends(get_session)) -> dict[str, Any]:
    def _count(model) -> int:
        return session.scalar(select(func.count(model.id))) or 0

    return {
        "sources": _count(Source),
        "articles": _count(Article),
        "observables": _count(Observable),
        "entities": _count(Entity),
        "claims": _count(Claim),
        "relationships": _count(Relationship),
        "cves": _count(CVE),
        "alerts": _count(Alert),
        "threat_feed_items": _count(ThreatFeedItem),
        "ransomware_feed_items": _count(RansomwareFeedItem),
        "open_reviews": session.scalar(
            select(func.count(AnalystReview.id)).where(AnalystReview.status == "open")
        )
        or 0,
        "failed_fetches_last_24h": session.scalar(
            select(func.count(SourceFetch.id)).where(
                SourceFetch.error.is_not(None),
                SourceFetch.fetched_at >= datetime.now(UTC) - timedelta(days=1),
            )
        )
        or 0,
    }


@api_router.get("/trending")
def trending(session: Session = Depends(get_session), hours: int = 24):
    since = datetime.now(UTC) - timedelta(hours=hours)
    from collections import Counter

    counter: Counter[str] = Counter()
    for art in session.scalars(select(Article).where(Article.ingested_at >= since)):
        for tag in art.tags or []:
            counter[tag] += 1
    return {"window_hours": hours, "tags": counter.most_common(20)}


@api_router.get("/reports/daily", response_class=PlainTextResponse)
def report_daily(since_hours: int = 24, session: Session = Depends(get_session)):
    return generate_daily_report(session, since_hours=since_hours)


@api_router.get("/reports/weekly", response_class=PlainTextResponse)
def report_weekly(session: Session = Depends(get_session)):
    return generate_weekly_report(session)


@api_router.post("/exports/json", response_class=PlainTextResponse)
def export_json(target: str = Query("articles"), session: Session = Depends(get_session)):
    if target == "articles":
        return export_articles_json(session)
    if target == "observables":
        return export_observables_json(session)
    raise HTTPException(422, detail="target must be articles|observables")


@api_router.post("/exports/csv", response_class=PlainTextResponse)
def export_csv(session: Session = Depends(get_session)):
    return export_observables_csv(session)


@api_router.post("/exports/stix-like", response_class=PlainTextResponse)
def export_stix(session: Session = Depends(get_session)):
    return export_stix_like_bundle(session)


@api_router.post("/decay/run")
def run_decay(session: Session = Depends(get_session)):
    res = LifecycleEngine(session).apply_decay()
    return {"expired": res.expired, "refreshed": res.refreshed}


# ---------- Threat Feeds (Intel Feeds) ----------


@api_router.get("/intel-feeds/threat-feeds")
def list_threat_feeds(
    session: Session = Depends(get_session),
    q: str | None = None,
    category: str | None = None,
    network: str | None = None,
    country: str | None = None,
    threat_actor: str | None = None,
    sort: str = "date_desc",
    limit: int = Query(100, ge=1, le=1000),
    offset: int = 0,
):
    stmt = select(ThreatFeedItem)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            (ThreatFeedItem.title.ilike(like))
            | (ThreatFeedItem.content.ilike(like))
            | (ThreatFeedItem.threat_actors.ilike(like))
            | (ThreatFeedItem.victim_site.ilike(like))
        )
    if category:
        stmt = stmt.where(ThreatFeedItem.category == category)
    if network:
        stmt = stmt.where(ThreatFeedItem.network == network)
    if country:
        stmt = stmt.where(ThreatFeedItem.victim_country == country)
    if threat_actor:
        stmt = stmt.where(ThreatFeedItem.threat_actors.ilike(f"%{threat_actor}%"))
    if sort == "risk_desc":
        stmt = stmt.order_by(ThreatFeedItem.risk_score.desc())
    elif sort == "date_asc":
        stmt = stmt.order_by(ThreatFeedItem.date.asc())
    else:
        stmt = stmt.order_by(ThreatFeedItem.date.desc())
    rows = session.scalars(stmt.limit(limit).offset(offset)).all()
    return [
        {
            "id": r.id,
            "uuid": r.uuid,
            "title": r.title,
            "date": r.date.isoformat() if r.date else None,
            "category": r.category,
            "network": r.network,
            "priority": r.priority,
            "content": r.content,
            "threat_actors": r.threat_actors,
            "victim_country": r.victim_country,
            "victim_industry": r.victim_industry,
            "victim_organization": r.victim_organization,
            "victim_site": r.victim_site,
            "published_url": r.published_url,
            "tags": r.tags,
            "risk_score": r.risk_score,
        }
        for r in rows
    ]


@api_router.get("/intel-feeds/threat-feeds/stats")
def threat_feed_stats(session: Session = Depends(get_session)):
    total = session.scalar(select(func.count(ThreatFeedItem.id))) or 0
    by_cat = session.execute(
        select(ThreatFeedItem.category, func.count(ThreatFeedItem.id))
        .group_by(ThreatFeedItem.category)
        .order_by(func.count(ThreatFeedItem.id).desc())
    ).all()
    by_net = session.execute(
        select(ThreatFeedItem.network, func.count(ThreatFeedItem.id))
        .group_by(ThreatFeedItem.network)
        .order_by(func.count(ThreatFeedItem.id).desc())
    ).all()
    return {
        "total": total,
        "by_category": {r[0] or "Unknown": r[1] for r in by_cat},
        "by_network": {r[0] or "Unknown": r[1] for r in by_net},
    }


@api_router.get("/intel-feeds/threat-feeds/{item_id}")
def get_threat_feed_item(item_id: int, session: Session = Depends(get_session)):
    item = session.get(ThreatFeedItem, item_id)
    if not item:
        raise HTTPException(404, "Threat feed item not found")
    return {
        "id": item.id,
        "uuid": item.uuid,
        "title": item.title,
        "date": item.date.isoformat() if item.date else None,
        "category": item.category,
        "network": item.network,
        "priority": item.priority,
        "content": item.content,
        "threat_actors": item.threat_actors,
        "victim_country": item.victim_country,
        "victim_industry": item.victim_industry,
        "victim_organization": item.victim_organization,
        "victim_site": item.victim_site,
        "published_url": item.published_url,
        "forum_section": item.forum_section,
        "screenshots": item.screenshots,
        "tags": item.tags,
        "risk_score": item.risk_score,
        "ingested_at": item.ingested_at.isoformat() if item.ingested_at else None,
    }


# ========================= Intel Feeds — Ransomware Feeds =========================


@api_router.get("/intel-feeds/ransomware-feeds")
def list_ransomware_feed(
    session: Session = Depends(get_session),
    q: str = "",
    group: str = "",
    country: str = "",
    industry: str = "",
    sort: str = "discovered_desc",
    limit: int = Query(50, ge=1, le=500),
    offset: int = 0,
):
    from sqlalchemy import or_ as _or

    stmt = select(RansomwareFeedItem)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            _or(
                RansomwareFeedItem.post_title.ilike(like),
                RansomwareFeedItem.description.ilike(like),
                RansomwareFeedItem.victim_website.ilike(like),
                RansomwareFeedItem.group_name.ilike(like),
            )
        )
    if group:
        stmt = stmt.where(RansomwareFeedItem.group_name == group)
    if country:
        stmt = stmt.where(RansomwareFeedItem.victim_country == country)
    if industry:
        stmt = stmt.where(RansomwareFeedItem.activity == industry)

    if sort == "risk_desc":
        stmt = stmt.order_by(RansomwareFeedItem.risk_score.desc().nullslast())
    elif sort == "discovered_asc":
        stmt = stmt.order_by(RansomwareFeedItem.discovered.asc())
    elif sort == "published_desc":
        stmt = stmt.order_by(RansomwareFeedItem.published.desc().nullslast())
    else:
        stmt = stmt.order_by(RansomwareFeedItem.discovered.desc().nullslast())

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = list(session.scalars(stmt.limit(limit).offset(offset)).all())
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "id": it.id,
                "post_title": it.post_title,
                "group_name": it.group_name,
                "discovered": it.discovered.isoformat() if it.discovered else None,
                "published": it.published.isoformat() if it.published else None,
                "victim_country": it.victim_country,
                "activity": it.activity,
                "victim_website": it.victim_website,
                "claim_url": it.claim_url,
                "tags": it.tags,
                "risk_score": it.risk_score,
            }
            for it in items
        ],
    }


@api_router.get("/intel-feeds/ransomware-feeds/stats")
def ransomware_feed_stats(session: Session = Depends(get_session)):
    total = session.scalar(select(func.count(RansomwareFeedItem.id))) or 0
    by_group = session.execute(
        select(RansomwareFeedItem.group_name, func.count(RansomwareFeedItem.id))
        .where(RansomwareFeedItem.group_name.isnot(None))
        .group_by(RansomwareFeedItem.group_name)
        .order_by(func.count(RansomwareFeedItem.id).desc())
        .limit(20)
    ).all()
    by_country = session.execute(
        select(RansomwareFeedItem.victim_country, func.count(RansomwareFeedItem.id))
        .where(RansomwareFeedItem.victim_country.isnot(None))
        .group_by(RansomwareFeedItem.victim_country)
        .order_by(func.count(RansomwareFeedItem.id).desc())
        .limit(20)
    ).all()
    by_industry = session.execute(
        select(RansomwareFeedItem.activity, func.count(RansomwareFeedItem.id))
        .where(RansomwareFeedItem.activity.isnot(None))
        .group_by(RansomwareFeedItem.activity)
        .order_by(func.count(RansomwareFeedItem.id).desc())
    ).all()
    return {
        "total": total,
        "by_group": {r[0]: r[1] for r in by_group},
        "by_country": {r[0]: r[1] for r in by_country},
        "by_industry": {r[0]: r[1] for r in by_industry},
    }


@api_router.get("/intel-feeds/ransomware-feeds/{item_id}")
def get_ransomware_feed_item(item_id: int, session: Session = Depends(get_session)):
    item = session.get(RansomwareFeedItem, item_id)
    if not item:
        raise HTTPException(404, "Ransomware feed item not found")
    return {
        "id": item.id,
        "post_hash": item.post_hash,
        "post_title": item.post_title,
        "group_name": item.group_name,
        "discovered": item.discovered.isoformat() if item.discovered else None,
        "published": item.published.isoformat() if item.published else None,
        "description": item.description,
        "activity": item.activity,
        "victim_website": item.victim_website,
        "victim_country": item.victim_country,
        "post_url": item.post_url,
        "claim_url": item.claim_url,
        "tags": item.tags,
        "risk_score": item.risk_score,
        "ingested_at": item.ingested_at.isoformat() if item.ingested_at else None,
    }
