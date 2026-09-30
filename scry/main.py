"""FastAPI application entrypoint."""

from __future__ import annotations

import json
import re
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from scry.api import api_router
from scry.api.ai import ai_router
from scry.api.auth import require_api_key
from scry.api.chat import chat_router
from scry.api.deps import get_session
from scry.api.taxii import taxii_router
from scry.config import get_settings
from scry.db import get_engine, session_scope
from scry.logging import configure_logging, get_logger
from scry.models import (
    CVE,
    Alert,
    AnalystReview,
    Article,
    Base,
    Claim,
    Entity,
    EntityMention,
    Observable,
    ObservableMention,
    RansomwareFeedItem,
    Relationship,
    Source,
    SourceFetch,
    ThreatFeedItem,
)

_HERE = Path(__file__).resolve().parent
TEMPLATES_DIR = _HERE / "ui" / "templates"
STATIC_DIR = _HERE / "ui" / "static"

configure_logging()
_log = get_logger("startup")


def _ensure_db_ready() -> None:
    Base.metadata.create_all(bind=get_engine())
    try:
        from scry.ingestion.source_registry import SourceRegistry

        with session_scope() as session:
            res = SourceRegistry(session).sync_from_yaml()
        _log.info("startup_sources_synced", **res)
    except Exception as exc:
        _log.warning("startup_source_sync_failed", exc=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    _ensure_db_ready()
    yield


app = FastAPI(
    title="Scry",
    version="0.1.0",
    description="Defensive CTI collection, extraction, enrichment, correlation, search, and reporting.",
    lifespan=lifespan,
)

app.include_router(api_router, dependencies=[Depends(require_api_key)])
app.include_router(ai_router, dependencies=[Depends(require_api_key)])
app.include_router(chat_router, dependencies=[Depends(require_api_key)])
# Read-only TAXII 2.1 server — authenticated like the rest of the API when a
# key is configured (no discovery exemption).
app.include_router(taxii_router, dependencies=[Depends(require_api_key)])

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["format_number"] = lambda v: f"{int(v):,}" if v is not None else "0"


def _timeago(value) -> Markup | str:
    """Render a datetime as a relative-time <time> element ("3h ago").

    Timezone-naive datetimes are assumed UTC. The absolute time is available
    on hover via the title attribute. None renders as an em dash.
    """
    if value is None:
        return Markup('<time class="muted">—</time>')
    if not isinstance(value, datetime):
        return escape(str(value))
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    secs = max(0, int((datetime.now(UTC) - value).total_seconds()))
    if secs < 60:
        label = "just now"
    elif secs < 3600:
        label = f"{secs // 60}m ago"
    elif secs < 86400:
        label = f"{secs // 3600}h ago"
    else:
        label = f"{secs // 86400}d ago"
    iso = value.isoformat()
    absolute = value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return Markup(f'<time datetime="{iso}" title="{absolute}">{label}</time>')


templates.env.filters["timeago"] = _timeago


def _redirect_flash(url: str, message: str, kind: str = "success") -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(
        url=f"{url}{sep}{urlencode({'flash': message, 'flash_kind': kind})}", status_code=303
    )


# ------------------------- helpers -------------------------


def _tag_filter(column, tag: str):
    """SQLite-safe filter: match a quoted tag inside a JSON array column."""
    return cast(column, String).like(f'%"{tag}"%')


def _qs_extra(**kwargs) -> str:
    pairs = [(k, v) for k, v in kwargs.items() if v not in (None, "", False)]
    return ("&" + urlencode(pairs)) if pairs else ""


def _resolve_rel_target(session: Session, kind: str, oid: int) -> dict | None:
    """Best-effort resolution of a Relationship endpoint to an Entity or Observable."""
    if kind in {"threat_actor", "malware_family", "organization", "person", "location", "campaign", "tool"}:
        e = session.get(Entity, oid)
        if e:
            return {"kind": "entity", "id": e.id, "type": e.type, "label": e.canonical_name}
    o = session.get(Observable, oid)
    if o and o.type == kind:
        return {"kind": "observable", "id": o.id, "type": o.type, "label": o.normalized_value}
    return None


# ------------------------- dashboard -------------------------


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)):
    settings = get_settings()
    counts = {
        "articles": session.scalar(select(func.count(Article.id))) or 0,
        "observables": session.scalar(select(func.count(Observable.id))) or 0,
        "cves": session.scalar(select(func.count(CVE.id))) or 0,
        "threat_feed_items": session.scalar(select(func.count(ThreatFeedItem.id))) or 0,
        "ransomware_feed_items": session.scalar(select(func.count(RansomwareFeedItem.id))) or 0,
        "open_reviews": session.scalar(
            select(func.count(AnalystReview.id)).where(AnalystReview.status == "open")
        )
        or 0,
    }
    high_risk = list(
        session.scalars(
            select(Observable)
            .where(Observable.risk_score >= 70)
            .order_by(Observable.risk_score.desc())
            .limit(15)
        )
    )
    recent_articles = list(session.scalars(select(Article).order_by(Article.id.desc()).limit(20)))
    # Recent high-risk threat feed items
    recent_threats = list(
        session.scalars(
            select(ThreatFeedItem)
            .where(ThreatFeedItem.risk_score >= 75)
            .order_by(ThreatFeedItem.date.desc())
            .limit(8)
        )
    )
    # Feed freshness: most recent fetch or article ingestion, whichever is newer.
    last_collected = max(
        (
            ts
            for ts in (
                session.scalar(select(func.max(SourceFetch.fetched_at))),
                session.scalar(select(func.max(Article.ingested_at))),
            )
            if ts is not None
        ),
        default=None,
    )
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "counts": counts,
            "high_risk": high_risk,
            "articles": recent_articles,
            "recent_threats": recent_threats,
            "settings": settings,
            "last_collected": last_collected,
        },
    )


@app.post("/ui/ingest/run")
async def ui_ingest_run(request: Request, session: Session = Depends(get_session)):
    """UI counterpart of POST /ingest/run — same services, browser-friendly redirect."""
    from scry.ingestion.ingest_engine import IngestionEngine
    from scry.pipeline import CTIPipeline

    try:
        engine = IngestionEngine(session)
        res = await engine.ingest_all()
        pipeline = CTIPipeline(session)
        for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
            pipeline.process_article(art)
        msg = (
            f"Collection complete: {res.get('articles', 0)} articles, "
            f"{res.get('cves', 0)} CVEs, {res.get('errors', 0)} errors, "
            f"{res.get('blocked', 0)} blocked"
        )
        return _redirect_flash("/", msg, "success" if not res.get("errors") else "error")
    except Exception as exc:
        _log.warning("ui_ingest_run_failed", exc=str(exc))
        return _redirect_flash("/", f"Collection failed: {exc}", "error")


# ------------------------- articles -------------------------


@app.get("/ui/articles", response_class=HTMLResponse)
def ui_articles(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    tag: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Article).order_by(Article.id.desc())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(Article.title.ilike(like), Article.extracted_text.ilike(like), Article.summary.ilike(like))
        )
    if tag:
        stmt = stmt.where(_tag_filter(Article.tags, tag))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    articles = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {"q": q, "tag": tag, "limit": limit, "offset": offset, "qs": _qs_extra(q=q, tag=tag)}
    return templates.TemplateResponse(
        request, "articles.html", {"articles": articles, "total": total, "filters": filters}
    )


@app.get("/ui/articles/{article_id}", response_class=HTMLResponse)
def ui_article_detail(article_id: int, request: Request, session: Session = Depends(get_session)):
    article = session.get(Article, article_id)
    if not article:
        raise HTTPException(404)
    source = session.get(Source, article.source_id) if article.source_id else None

    rows = session.execute(
        select(Observable, ObservableMention)
        .join(ObservableMention, ObservableMention.observable_id == Observable.id)
        .where(ObservableMention.article_id == article_id)
        .order_by(Observable.risk_score.desc())
    ).all()
    observable_mentions = [(ob, mention) for ob, mention in rows]

    rows = session.execute(
        select(Entity, EntityMention)
        .join(EntityMention, EntityMention.entity_id == Entity.id)
        .where(EntityMention.article_id == article_id)
    ).all()
    entity_mentions = [(e, mention) for e, mention in rows]

    claims = list(session.scalars(select(Claim).where(Claim.article_id == article_id)))

    return templates.TemplateResponse(
        request,
        "article_detail.html",
        {
            "article": article,
            "source": source,
            "observable_mentions": observable_mentions,
            "entity_mentions": entity_mentions,
            "claims": claims,
        },
    )


# ------------------------- observables -------------------------


@app.get("/ui/observables", response_class=HTMLResponse)
def ui_observables(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    type: str | None = None,
    tag: str | None = None,
    min_risk: float | None = None,
    status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Observable).order_by(Observable.risk_score.desc(), Observable.id.desc())
    if q:
        stmt = stmt.where(Observable.normalized_value.ilike(f"%{q.lower()}%"))
    if type:
        stmt = stmt.where(Observable.type == type)
    if tag:
        stmt = stmt.where(_tag_filter(Observable.tags, tag))
    if min_risk is not None:
        stmt = stmt.where(Observable.risk_score >= min_risk)
    if status:
        stmt = stmt.where(Observable.status == status)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    obs = list(session.scalars(stmt.offset(offset).limit(limit)))

    available_types = [
        t
        for (t,) in session.execute(
            select(Observable.type).group_by(Observable.type).order_by(Observable.type)
        ).all()
    ]
    filters = {
        "q": q,
        "type": type,
        "tag": tag,
        "min_risk": min_risk,
        "status": status,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(q=q, type=type, tag=tag, min_risk=min_risk, status=status),
    }
    return templates.TemplateResponse(
        request,
        "observables.html",
        {"observables": obs, "total": total, "filters": filters, "available_types": available_types},
    )


@app.get("/ui/observables/{ob_id}", response_class=HTMLResponse)
def ui_observable_detail(ob_id: int, request: Request, session: Session = Depends(get_session)):
    ob = session.get(Observable, ob_id)
    if not ob:
        raise HTTPException(404)

    rows = session.execute(
        select(Article, ObservableMention)
        .join(ObservableMention, ObservableMention.article_id == Article.id)
        .where(ObservableMention.observable_id == ob_id)
        .order_by(Article.id.desc())
        .limit(50)
    ).all()
    mentions = [(art, mention) for art, mention in rows]

    rels: list[tuple[str, Relationship, dict | None]] = []
    out_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.source_type == ob.type, Relationship.source_id == ob.id)
            .limit(100)
        )
    )
    in_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.target_type == ob.type, Relationship.target_id == ob.id)
            .limit(100)
        )
    )
    for r in out_rels:
        rels.append(("out", r, _resolve_rel_target(session, r.target_type, r.target_id)))
    for r in in_rels:
        rels.append(("in", r, _resolve_rel_target(session, r.source_type, r.source_id)))

    enrichment_json = json.dumps(ob.enrichment or {}, indent=2, default=str)
    vt_status = (ob.enrichment or {}).get("virustotal_checked_at")
    otx_status = (ob.enrichment or {}).get("otx_checked_at")
    return templates.TemplateResponse(
        request,
        "observable_detail.html",
        {
            "observable": ob,
            "mentions": mentions,
            "relationships": rels,
            "enrichment_json": enrichment_json,
            "vt_provider_status": vt_status,
            "otx_provider_status": otx_status,
        },
    )


# ------------------------- CVEs -------------------------


@app.get("/ui/cves", response_class=HTMLResponse)
def ui_cves(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    vendor: str | None = None,
    severity: str | None = None,
    only_kev: bool = False,
    only_microsoft: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(CVE).order_by(CVE.kev.desc(), CVE.updated_at.desc())
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                CVE.cve_id.ilike(like.upper()),
                CVE.vendor.ilike(like),
                CVE.product.ilike(like),
                CVE.description.ilike(like),
            )
        )
    if vendor:
        stmt = stmt.where(CVE.vendor.ilike(f"%{vendor}%"))
    if severity:
        stmt = stmt.where(CVE.severity == severity)
    if only_kev:
        stmt = stmt.where(CVE.kev.is_(True))
    if only_microsoft:
        stmt = stmt.where(CVE.is_microsoft.is_(True))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    cves = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {
        "q": q,
        "vendor": vendor,
        "severity": severity,
        "only_kev": only_kev,
        "only_microsoft": only_microsoft,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(
            q=q,
            vendor=vendor,
            severity=severity,
            only_kev="true" if only_kev else None,
            only_microsoft="true" if only_microsoft else None,
        ),
    }
    return templates.TemplateResponse(
        request, "cves.html", {"cves": cves, "total": total, "filters": filters}
    )


@app.get("/ui/cves/{cve_id}", response_class=HTMLResponse)
def ui_cve_detail(cve_id: str, request: Request, session: Session = Depends(get_session)):
    cve = session.scalar(select(CVE).where(CVE.cve_id == cve_id.upper()))
    if not cve:
        raise HTTPException(404)
    needle = f"%{cve.cve_id}%"
    articles = list(
        session.scalars(
            select(Article)
            .where(or_(Article.title.ilike(needle), Article.extracted_text.ilike(needle)))
            .limit(50)
        )
    )
    return templates.TemplateResponse(request, "cve_detail.html", {"cve": cve, "articles": articles})


# ------------------------- entities -------------------------


@app.get("/ui/entities", response_class=HTMLResponse)
def ui_entities(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
    type: str | None = None,
    tag: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Entity).order_by(Entity.type, Entity.canonical_name)
    if q:
        stmt = stmt.where(Entity.canonical_name.ilike(f"%{q}%"))
    if type:
        stmt = stmt.where(Entity.type == type)
    if tag:
        stmt = stmt.where(_tag_filter(Entity.tags, tag))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    entities = list(session.scalars(stmt.offset(offset).limit(limit)))
    available_types = [
        t for (t,) in session.execute(select(Entity.type).group_by(Entity.type).order_by(Entity.type)).all()
    ]
    filters = {
        "q": q,
        "type": type,
        "tag": tag,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(q=q, type=type, tag=tag),
    }
    return templates.TemplateResponse(
        request,
        "entities.html",
        {"entities": entities, "total": total, "filters": filters, "available_types": available_types},
    )


@app.get("/ui/entities/{entity_id}", response_class=HTMLResponse)
def ui_entity_detail(entity_id: int, request: Request, session: Session = Depends(get_session)):
    ent = session.get(Entity, entity_id)
    if not ent:
        raise HTTPException(404)
    out_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.source_type == ent.type, Relationship.source_id == ent.id)
            .limit(2000)
        )
    )
    in_rels = list(
        session.scalars(
            select(Relationship)
            .where(Relationship.target_type == ent.type, Relationship.target_id == ent.id)
            .limit(2000)
        )
    )

    related_observables: list[tuple[Observable, str]] = []
    related_entities: list[tuple[Entity, str, str]] = []
    for r in out_rels:
        target = _resolve_rel_target(session, r.target_type, r.target_id)
        if target is None:
            continue
        if target["kind"] == "observable":
            o = session.get(Observable, target["id"])
            if o is not None:
                related_observables.append((o, r.relationship_type))
        else:
            e2 = session.get(Entity, target["id"])
            if e2 is not None and e2.id != ent.id:
                related_entities.append((e2, r.relationship_type, "out"))
    for r in in_rels:
        src = _resolve_rel_target(session, r.source_type, r.source_id)
        if src is None or src["kind"] != "entity":
            continue
        e2 = session.get(Entity, src["id"])
        if e2 is not None and e2.id != ent.id:
            related_entities.append((e2, r.relationship_type, "in"))

    related_observables.sort(key=lambda t: t[0].risk_score, reverse=True)
    related_observables = related_observables[:500]
    related_entities = related_entities[:200]

    rows = session.execute(
        select(Article)
        .join(EntityMention, EntityMention.article_id == Article.id)
        .where(EntityMention.entity_id == ent.id)
        .order_by(Article.id.desc())
        .limit(50)
    ).all()
    articles = [a for (a,) in rows]
    return templates.TemplateResponse(
        request,
        "entity_detail.html",
        {
            "entity": ent,
            "related_observables": related_observables,
            "related_entities": related_entities,
            "articles": articles,
        },
    )


# ------------------------- reviews -------------------------

_BULK_ACTIONS = {"approve": "true_positive", "reject": "false_positive"}


@app.post("/ui/reviews/bulk")
def ui_reviews_bulk(
    request: Request,
    session: Session = Depends(get_session),
    review_ids: list[int] = Form(default=[]),
    action: str = Form(default=""),
):
    disposition = _BULK_ACTIONS.get(action)
    if disposition is None:
        return _redirect_flash("/ui/reviews", f"Unknown bulk action: {action or '(none)'}", "error")
    rows = list(
        session.scalars(
            select(AnalystReview).where(
                AnalystReview.id.in_(review_ids or []), AnalystReview.status == "open"
            )
        )
    )
    now = datetime.now(UTC)
    for row in rows:
        row.status = "closed"
        row.disposition = disposition
        row.reviewed_at = now
    session.commit()
    verb = "approved" if action == "approve" else "rejected"
    return _redirect_flash("/ui/reviews", f"{len(rows)} reviews {verb}")


@app.get("/ui/reviews", response_class=HTMLResponse)
def ui_reviews(
    request: Request,
    session: Session = Depends(get_session),
    status: str = "open",
    item_type: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(AnalystReview).order_by(AnalystReview.id.desc())
    if status and status != "any":
        stmt = stmt.where(AnalystReview.status == status)
    if item_type:
        stmt = stmt.where(AnalystReview.item_type == item_type)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {
        "status": status,
        "item_type": item_type,
        "limit": limit,
        "offset": offset,
        "qs": _qs_extra(status=status, item_type=item_type),
    }
    return templates.TemplateResponse(
        request, "reviews.html", {"rows": rows, "total": total, "filters": filters}
    )


@app.get("/ui/reviews/{review_id}", response_class=HTMLResponse)
def ui_review_detail(review_id: int, request: Request, session: Session = Depends(get_session)):
    r = session.get(AnalystReview, review_id)
    if not r:
        raise HTTPException(404)
    linked_url = None
    if r.item_type == "observable":
        linked_url = f"/ui/observables/{r.item_id}"
    elif r.item_type == "claim":
        c = session.get(Claim, r.item_id)
        if c is not None:
            linked_url = f"/ui/articles/{c.article_id}"
    elif r.item_type == "entity":
        linked_url = f"/ui/entities/{r.item_id}"
    correction_json = json.dumps(r.correction or {}, indent=2, default=str) if r.correction else ""
    return templates.TemplateResponse(
        request,
        "review_detail.html",
        {"review": r, "linked_url": linked_url, "correction_json": correction_json},
    )


@app.post("/ui/reviews/{review_id}", response_class=HTMLResponse)
def ui_review_patch(
    review_id: int,
    request: Request,
    session: Session = Depends(get_session),
    status: str | None = Form(None),
    disposition: str | None = Form(None),
    analyst: str | None = Form(None),
    comments: str | None = Form(None),
):
    from scry.review import ReviewQueue

    queue = ReviewQueue(session)
    queue.update(
        review_id,
        status=status or None,
        disposition=disposition or None,
        analyst=analyst or None,
        comments=comments or None,
        correction=None,
    )
    return _redirect_flash(f"/ui/reviews/{review_id}", f"Review #{review_id} updated")


# ------------------------- alerts -------------------------


@app.get("/ui/alerts", response_class=HTMLResponse)
def ui_alerts(
    request: Request,
    session: Session = Depends(get_session),
    limit: int = Query(100, ge=1, le=500),
    offset: int = 0,
):
    stmt = select(Alert).order_by(Alert.id.desc())
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    alerts = list(session.scalars(stmt.offset(offset).limit(limit)))
    filters = {"limit": limit, "offset": offset, "qs": ""}
    from scry.alerting.channels import channel_status
    from scry.enrichment.provider_settings import PROVIDER_META, load_provider_states

    states = load_provider_states(session)
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "alerts": alerts,
            "total": total,
            "filters": filters,
            "channels": channel_status(),
            "outbound_enabled": get_settings().enable_outbound_alerts,
            "enrichment_providers": [states[name].as_dict() for name in PROVIDER_META],
        },
    )


# ------------------------- tags -------------------------

_TAG_BUCKET_BREAKS = (50, 200, 800)


@app.get("/ui/tags", response_class=HTMLResponse)
def ui_tags(
    request: Request,
    session: Session = Depends(get_session),
    q: str | None = None,
):
    counter: Counter[str] = Counter()
    for (tags_json,) in session.execute(select(Observable.tags)):
        for t in tags_json or []:
            counter[t] += 1
    for (tags_json,) in session.execute(select(Article.tags)):
        for t in tags_json or []:
            counter[t] += 1
    for (tags_json,) in session.execute(select(Entity.tags)):
        for t in tags_json or []:
            counter[t] += 1

    if q:
        needle = q.lower()
        counter = Counter({t: n for t, n in counter.items() if needle in t.lower()})

    buckets: list[tuple[str, int, str]] = []
    for tag, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
        if count >= _TAG_BUCKET_BREAKS[2]:
            size = "xl"
        elif count >= _TAG_BUCKET_BREAKS[1]:
            size = "l"
        elif count >= _TAG_BUCKET_BREAKS[0]:
            size = "m"
        else:
            size = "s"
        buckets.append((tag, count, size))

    return templates.TemplateResponse(request, "tags.html", {"tag_buckets": buckets, "filters": {"q": q}})


@app.get("/ui/tags/{tag:path}", response_class=HTMLResponse)
def ui_tag_detail(tag: str, request: Request, session: Session = Depends(get_session)):
    decoded = re.sub(r"\+", " ", tag)
    observables = list(
        session.scalars(
            select(Observable)
            .where(_tag_filter(Observable.tags, decoded))
            .order_by(Observable.risk_score.desc())
            .limit(500)
        )
    )
    articles = list(
        session.scalars(
            select(Article).where(_tag_filter(Article.tags, decoded)).order_by(Article.id.desc()).limit(200)
        )
    )
    entities = list(
        session.scalars(
            select(Entity).where(_tag_filter(Entity.tags, decoded)).order_by(Entity.canonical_name).limit(200)
        )
    )
    return templates.TemplateResponse(
        request,
        "tag_detail.html",
        {"tag": decoded, "observables": observables, "articles": articles, "entities": entities},
    )


# ------------------------- sources -------------------------


@app.get("/ui/sources", response_class=HTMLResponse)
def ui_sources(request: Request, session: Session = Depends(get_session)):
    sources = list(
        session.scalars(select(Source).order_by(Source.enabled.desc(), Source.baseline_confidence.desc()))
    )
    enabled_count = sum(1 for s in sources if s.enabled)
    return templates.TemplateResponse(
        request,
        "sources.html",
        {"sources": sources, "total": len(sources), "enabled_count": enabled_count},
    )


# ------------------------- search -------------------------


@app.get("/ui/search", response_class=HTMLResponse)
def ui_search(request: Request, q: str = "", session: Session = Depends(get_session)):
    from scry.search import full_text_search

    hits = full_text_search(session, q, limit=50) if q else []
    return templates.TemplateResponse(
        request,
        "search.html",
        {"q": q, "hits": hits, "enable_ai_search": get_settings().enable_ai_search},
    )


# ========================= Intel Feeds — Threat Feeds =========================


@app.get("/ui/intel-feeds/threat-feeds", response_class=HTMLResponse)
def ui_threat_feeds(
    request: Request,
    session: Session = Depends(get_session),
    q: str = "",
    category: str = "",
    network: str = "",
    country: str = "",
    sort: str = "date_desc",
    limit: int = Query(50, ge=1, le=200),
    offset: int = 0,
):
    from sqlalchemy import String as _String
    from sqlalchemy import cast as _cast

    stmt = select(ThreatFeedItem)

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                ThreatFeedItem.title.ilike(like),
                ThreatFeedItem.content.ilike(like),
                ThreatFeedItem.threat_actors.ilike(like),
                ThreatFeedItem.victim_site.ilike(like),
                ThreatFeedItem.victim_organization.ilike(like),
                _cast(ThreatFeedItem.tags, _String).ilike(like),
            )
        )
    if category:
        stmt = stmt.where(ThreatFeedItem.category == category)
    if network:
        stmt = stmt.where(ThreatFeedItem.network == network)
    if country:
        stmt = stmt.where(ThreatFeedItem.victim_country == country)

    # Sorting
    if sort == "risk_desc":
        stmt = stmt.order_by(ThreatFeedItem.risk_score.desc().nullslast(), ThreatFeedItem.date.desc())
    elif sort == "date_asc":
        stmt = stmt.order_by(ThreatFeedItem.date.asc())
    else:
        stmt = stmt.order_by(ThreatFeedItem.date.desc().nullslast())

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = list(session.scalars(stmt.limit(limit).offset(offset)).all())

    # Aggregates for filters (computed once across all records, not just filtered)
    all_cats = session.execute(
        select(ThreatFeedItem.category, func.count(ThreatFeedItem.id).label("c"))
        .group_by(ThreatFeedItem.category)
        .order_by(func.count(ThreatFeedItem.id).desc())
    ).all()
    cat_counts = [(row[0] or "Unknown", row[1]) for row in all_cats if row[0]]

    networks = [
        row[0]
        for row in session.execute(
            select(ThreatFeedItem.network).distinct().where(ThreatFeedItem.network.isnot(None))
        ).all()
    ]

    countries = [
        row[0]
        for row in session.execute(
            select(ThreatFeedItem.victim_country)
            .where(ThreatFeedItem.victim_country.isnot(None))
            .group_by(ThreatFeedItem.victim_country)
            .order_by(func.count(ThreatFeedItem.id).desc())
            .limit(40)
        ).all()
    ]

    qs = _qs_extra(q=q, category=category, network=network, country=country, sort=sort)
    filters = dict(
        q=q, category=category, network=network, country=country, sort=sort, offset=offset, limit=limit, qs=qs
    )

    return templates.TemplateResponse(
        request,
        "threat_feeds.html",
        {
            "items": items,
            "total": total,
            "cat_counts": cat_counts,
            "networks": sorted(networks),
            "countries": countries,
            "categories": [c for c, _ in cat_counts],
            "filters": filters,
        },
    )


@app.get("/ui/intel-feeds/threat-feeds/{item_id}", response_class=HTMLResponse)
def ui_threat_feed_detail(item_id: int, request: Request, session: Session = Depends(get_session)):
    item = session.get(ThreatFeedItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Threat feed item not found")

    # Related items from same actor
    related = []
    if item.threat_actors:
        related = list(
            session.scalars(
                select(ThreatFeedItem)
                .where(ThreatFeedItem.threat_actors == item.threat_actors)
                .where(ThreatFeedItem.id != item.id)
                .order_by(ThreatFeedItem.date.desc())
                .limit(10)
            ).all()
        )

    return templates.TemplateResponse(
        request,
        "threat_feed_detail.html",
        {
            "item": item,
            "related": related,
        },
    )


# ========================= Intel Feeds — Ransomware Feeds =========================


@app.get("/ui/intel-feeds/ransomware-feeds", response_class=HTMLResponse)
def ui_ransomware_feeds(
    request: Request,
    session: Session = Depends(get_session),
    q: str = "",
    group: str = "",
    country: str = "",
    industry: str = "",
    sort: str = "discovered_desc",
    limit: int = Query(50, ge=1, le=200),
    offset: int = 0,
):
    from sqlalchemy import String as _String
    from sqlalchemy import cast as _cast

    stmt = select(RansomwareFeedItem)

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                RansomwareFeedItem.post_title.ilike(like),
                RansomwareFeedItem.description.ilike(like),
                RansomwareFeedItem.victim_website.ilike(like),
                RansomwareFeedItem.group_name.ilike(like),
                _cast(RansomwareFeedItem.tags, _String).ilike(like),
            )
        )
    if group:
        stmt = stmt.where(RansomwareFeedItem.group_name == group)
    if country:
        stmt = stmt.where(RansomwareFeedItem.victim_country == country)
    if industry:
        stmt = stmt.where(RansomwareFeedItem.activity == industry)

    # Sorting
    if sort == "risk_desc":
        stmt = stmt.order_by(
            RansomwareFeedItem.risk_score.desc().nullslast(), RansomwareFeedItem.discovered.desc()
        )
    elif sort == "discovered_asc":
        stmt = stmt.order_by(RansomwareFeedItem.discovered.asc())
    elif sort == "published_desc":
        stmt = stmt.order_by(RansomwareFeedItem.published.desc().nullslast())
    else:
        stmt = stmt.order_by(RansomwareFeedItem.discovered.desc().nullslast())

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = list(session.scalars(stmt.limit(limit).offset(offset)).all())

    # Aggregates (global, not filtered)
    group_counts = [
        (row[0], row[1])
        for row in session.execute(
            select(RansomwareFeedItem.group_name, func.count(RansomwareFeedItem.id).label("c"))
            .where(RansomwareFeedItem.group_name.isnot(None))
            .group_by(RansomwareFeedItem.group_name)
            .order_by(func.count(RansomwareFeedItem.id).desc())
        ).all()
        if row[0]
    ]
    groups = [g for g, _ in group_counts]

    countries = [
        row[0]
        for row in session.execute(
            select(RansomwareFeedItem.victim_country)
            .where(RansomwareFeedItem.victim_country.isnot(None))
            .group_by(RansomwareFeedItem.victim_country)
            .order_by(func.count(RansomwareFeedItem.id).desc())
            .limit(60)
        ).all()
    ]

    industries = [
        row[0]
        for row in session.execute(
            select(RansomwareFeedItem.activity)
            .where(RansomwareFeedItem.activity.isnot(None))
            .group_by(RansomwareFeedItem.activity)
            .order_by(func.count(RansomwareFeedItem.id).desc())
        ).all()
    ]

    qs = _qs_extra(q=q, group=group, country=country, industry=industry, sort=sort)
    filters = dict(
        q=q, group=group, country=country, industry=industry, sort=sort, offset=offset, limit=limit, qs=qs
    )

    return templates.TemplateResponse(
        request,
        "ransomware_feeds.html",
        {
            "items": items,
            "total": total,
            "group_counts": group_counts,
            "groups": groups,
            "countries": countries,
            "industries": industries,
            "filters": filters,
        },
    )


@app.get("/ui/intel-feeds/ransomware-feeds/{item_id}", response_class=HTMLResponse)
def ui_ransomware_feed_detail(item_id: int, request: Request, session: Session = Depends(get_session)):
    item = session.get(RansomwareFeedItem, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Ransomware feed item not found")

    # Other victims from the same group (most recent 10)
    related = []
    if item.group_name:
        related = list(
            session.scalars(
                select(RansomwareFeedItem)
                .where(RansomwareFeedItem.group_name == item.group_name)
                .where(RansomwareFeedItem.id != item.id)
                .order_by(RansomwareFeedItem.discovered.desc())
                .limit(10)
            ).all()
        )

    # Other victims from same country (different group, most recent 8)
    country_peers = []
    if item.victim_country:
        country_peers = list(
            session.scalars(
                select(RansomwareFeedItem)
                .where(RansomwareFeedItem.victim_country == item.victim_country)
                .where(RansomwareFeedItem.id != item.id)
                .order_by(RansomwareFeedItem.discovered.desc())
                .limit(8)
            ).all()
        )

    return templates.TemplateResponse(
        request,
        "ransomware_feed_detail.html",
        {
            "item": item,
            "related": related,
            "country_peers": country_peers,
        },
    )
