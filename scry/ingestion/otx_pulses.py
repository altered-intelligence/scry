"""OTX pulse ingestion (v0.6.0 step 1).

Subscribes to AlienVault OTX pulses matching configured queries/tags and
stores each pulse as an Article so the existing extraction/enrichment
pipeline picks up its IOCs. Pulses are deduplicated by pulse page URL;
re-pulling unchanged pulses updates nothing.

Key resolution (locked v0.5 rule):
- background/scheduled pulls use the SYSTEM OTX key (env/DB chain via
  ``scry.enrichment.provider_settings``);
- user-triggered pulls use the ACTING USER's personal OTX key
  (``scry.enrichment.user_keys``);
- neither → the feature is a clean no-op with a clear message.

Key material is NEVER logged: the client only attaches it as a header and
no code path writes it to logs, flashes, or error strings.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.config import load_otx_pulse_subscriptions
from scry.logging import get_logger
from scry.models import Article, Source, SystemSetting
from scry.search import embeddings, fts

logger = get_logger("otx_pulses")

OTX_BASE_URL = "https://otx.alienvault.com"
SEARCH_URL = f"{OTX_BASE_URL}/api/v1/search/pulses"
PULSE_DETAIL_URL = f"{OTX_BASE_URL}/api/v1/pulses/{{pulse_id}}"
PULSE_PAGE_URL = f"{OTX_BASE_URL}/pulse/{{pulse_id}}"
PARSER_VERSION = "0.1"

DEFAULT_MAX_PULSE_AGE_DAYS = 30
DEFAULT_LIMIT = 25

# SystemSetting keys for per-subscription last-run stats.


def _last_run_key(name: str) -> str:
    return f"otx_pulse.{name}.last_run"


@dataclass
class PulseSubscription:
    name: str
    query: str
    tags: list[str] = field(default_factory=list)
    max_pulse_age_days: int = DEFAULT_MAX_PULSE_AGE_DAYS
    limit: int = DEFAULT_LIMIT

    @property
    def source_name(self) -> str:
        return f"otx_pulse:{self.name}"


def load_subscriptions(path: str | None = None) -> list[PulseSubscription]:
    """Load + validate config/otx_pulses.yaml. Invalid entries are skipped."""
    specs = _read_subscription_yaml(path)
    subs: list[PulseSubscription] = []
    for spec in specs:
        if not isinstance(spec, dict):
            logger.warning("otx_pulse_subscription_invalid", reason="not a mapping")
            continue
        name = str(spec.get("name") or "").strip()
        query = str(spec.get("query") or "").strip()
        if not name:
            logger.warning("otx_pulse_subscription_invalid", reason="missing name")
            continue
        if not query:
            logger.warning("otx_pulse_subscription_skipped", name=name, reason="empty query")
            continue
        raw_tags = spec.get("tags") or []
        if not isinstance(raw_tags, list):
            logger.warning("otx_pulse_subscription_invalid", name=name, reason="tags not a list")
            continue
        try:
            max_age = int(spec.get("max_pulse_age_days", DEFAULT_MAX_PULSE_AGE_DAYS))
            limit = int(spec.get("limit", DEFAULT_LIMIT))
        except (TypeError, ValueError):
            logger.warning("otx_pulse_subscription_invalid", name=name, reason="bad numbers")
            continue
        subs.append(
            PulseSubscription(
                name=name,
                query=query,
                tags=[str(t).strip() for t in raw_tags if str(t).strip()],
                max_pulse_age_days=max(0, max_age),
                limit=max(1, min(limit, 100)),
            )
        )
    return subs


def _read_subscription_yaml(path: str | None) -> list[Any]:
    if path is not None:
        import yaml

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError("otx_pulses.yaml must be a mapping at top level")
        return list(data.get("subscriptions", []))
    return load_otx_pulse_subscriptions()


def resolve_key(session: Session, acting_user: Any | None) -> tuple[str, str]:
    """Resolve the OTX key per the locked rule.

    Returns (key, source) where source is "personal" | "system" | "".
    An acting user without a personal key gets ("", "") — user-triggered
    pulls never silently fall back to the system key (v0.5 rule).
    """
    if acting_user is not None:
        from scry.enrichment.user_keys import get_decrypted_key

        key = get_decrypted_key(session, acting_user.id, "otx")
        return (key, "personal") if key else ("", "")

    from scry.enrichment.provider_settings import load_provider_states

    key = load_provider_states(session)["otx"].api_key
    return (key, "system") if key else ("", "")


class OTXPulseClient:
    """Thin httpx client for the OTX pulse search API. Caller supplies the key."""

    def __init__(self, api_key: str, *, timeout: float = 45.0) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            headers={"X-OTX-API-KEY": api_key, "User-Agent": "Scry/0.1"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> OTXPulseClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def search_pulses(self, query: str, *, limit: int) -> list[dict[str, Any]]:
        """Search pulses newest-modified first; returns up to ``limit`` pulse dicts.

        OTX is slow under load — one retry on read timeout.
        """
        params = {"q": query, "sort": "-modified", "limit": limit, "page": 1}
        for attempt in (1, 2):
            try:
                r = self._client.get(SEARCH_URL, params=params)
                r.raise_for_status()
                data = r.json()
                results = data.get("results") or []
                return [p for p in results if isinstance(p, dict)][:limit]
            except httpx.TimeoutException:
                if attempt == 2:
                    raise
        return []

    def get_pulse(self, pulse_id: str) -> dict[str, Any]:
        """Fetch one pulse's full detail (search results omit tags).

        OTX detail endpoints are slow under burst — one retry on read timeout.
        """
        url = PULSE_DETAIL_URL.format(pulse_id=pulse_id)
        for attempt in (1, 2):
            try:
                r = self._client.get(url)
                r.raise_for_status()
                data = r.json()
                return data if isinstance(data, dict) else {}
            except httpx.TimeoutException:
                if attempt == 2:
                    raise
        return {}


def _parse_ts(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _pulse_tags(pulse: dict[str, Any]) -> list[str]:
    tags = pulse.get("tags") or []
    return [str(t) for t in tags if str(t).strip()]


def _content_hash(pulse: dict[str, Any]) -> str:
    basis = json.dumps(
        {
            "name": pulse.get("name") or "",
            "description": pulse.get("description") or "",
            "created": pulse.get("created") or "",
            "tlp": pulse.get("TLP") or pulse.get("tlp") or "",
        },
        sort_keys=True,
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _ensure_source(session: Session, sub: PulseSubscription) -> Source:
    """One Source row per subscription (named otx_pulse:<name>); NOT a feed
    source — created disabled so ingest_all never tries to RSS-fetch it."""
    src = session.scalar(select(Source).where(Source.name == sub.source_name))
    if src is None:
        src = Source(
            name=sub.source_name,
            type="otx_pulse",
            url=OTX_BASE_URL,
            enabled=False,
            priority="medium",
            baseline_confidence=80,
            collection_policy="safe_public_web",
            independent=True,
            rate_limit_per_minute=10,
            tags=["otx", "pulse", *sub.tags],
            notes="Created automatically by OTX pulse ingestion (v0.6.0).",
        )
        session.add(src)
        session.flush()
    return src


def pull_subscription(client: OTXPulseClient, sub: PulseSubscription, session: Session) -> dict[str, int]:
    """Pull one subscription: search pulses, persist new/changed ones as Articles.

    Idempotent: an unchanged pulse (same content hash) is counted as skipped
    and left untouched. Returns counts added/skipped/updated/filtered.
    """
    source = _ensure_source(session, sub)
    now = datetime.now(UTC)
    counts = {"added": 0, "skipped": 0, "updated": 0, "filtered": 0}
    touched_ids: list[int] = []

    pulses = client.search_pulses(sub.query, limit=sub.limit)
    for pulse in pulses:
        pulse_id = str(pulse.get("id") or "").strip()
        if not pulse_id:
            counts["filtered"] += 1
            continue
        created = _parse_ts(pulse.get("created"))
        if sub.max_pulse_age_days and created and created < now - timedelta(days=sub.max_pulse_age_days):
            counts["filtered"] += 1
            continue
        tags = _pulse_tags(pulse)
        if sub.tags and not {t.lower() for t in sub.tags} & {t.lower() for t in tags}:
            # OTX search results omit tags (always []) — fetch the pulse
            # detail before rejecting on a tag filter.
            # (live incident 2026-09-30: an all-25-filtered pull)
            try:
                detail = client.get_pulse(pulse_id)
            except Exception as exc:
                logger.warning("otx_pulse_detail_failed", pulse_id=pulse_id, error=str(exc))
                detail = {}
            detail_tags = _pulse_tags(detail)
            if detail_tags:
                tags = detail_tags
            if not {t.lower() for t in sub.tags} & {t.lower() for t in tags}:
                counts["filtered"] += 1
                continue

        url = PULSE_PAGE_URL.format(pulse_id=pulse_id)
        title = (pulse.get("name") or "").strip() or "(untitled pulse)"
        summary = (pulse.get("description") or "").strip()
        content_hash = _content_hash(pulse)
        merged_tags = sorted(set(tags) | set(sub.tags))

        existing = session.scalar(select(Article).where(Article.url == url))
        if existing is not None:
            if existing.content_hash == content_hash:
                counts["skipped"] += 1
                continue
            existing.title = title
            existing.summary = summary
            existing.extracted_text = summary[:50_000]
            existing.published_at = created
            existing.tags = merged_tags
            existing.content_hash = content_hash
            # Reset extractor version so the pipeline re-runs IOC extraction
            existing.extractor_version = "0"
            touched_ids.append(existing.id)
            counts["updated"] += 1
            continue

        article = Article(
            source_id=source.id,
            title=title,
            url=url,
            published_at=created,
            ingested_at=now,
            extracted_text=summary[:50_000],
            summary=summary,
            content_hash=content_hash,
            source_confidence=source.baseline_confidence,
            parser_version=PARSER_VERSION,
            tags=merged_tags,
        )
        session.add(article)
        session.flush()
        touched_ids.append(article.id)
        counts["added"] += 1

    session.commit()
    # Keep the FTS5 index + embeddings in sync for new/changed pulse articles (best-effort).
    try:
        fts.index_rows(session, "article", touched_ids)
        embeddings.sync_article_embeddings(session, touched_ids)
        session.commit()
    except Exception as exc:  # pragma: no cover - defensive
        session.rollback()
        logger.warning("fts_index_failed", exc=str(exc))
    return counts


def record_last_run(session: Session, sub: PulseSubscription, counts: dict[str, int]) -> None:
    """Persist per-subscription last-run stats into SystemSetting."""
    key = _last_run_key(sub.name)
    row = session.scalar(select(SystemSetting).where(SystemSetting.key == key))
    payload = json.dumps({"at": datetime.now(UTC).isoformat(), **counts})
    if row is None:
        session.add(SystemSetting(key=key, value=payload))
    else:
        row.value = payload
    session.flush()


def last_run_stats(session: Session, subs: list[PulseSubscription]) -> dict[str, dict[str, Any]]:
    """last-run stats per subscription name ({} when never pulled)."""
    out: dict[str, dict[str, Any]] = {}
    for sub in subs:
        row = session.scalar(select(SystemSetting).where(SystemSetting.key == _last_run_key(sub.name)))
        if row is None:
            out[sub.name] = {}
            continue
        try:
            out[sub.name] = json.loads(row.value)
        except (ValueError, TypeError):
            out[sub.name] = {}
    return out


def pull_all(
    session: Session,
    *,
    api_key: str,
    subscriptions: list[PulseSubscription] | None = None,
) -> dict[str, dict[str, int]]:
    """Pull all (or the named) subscriptions with one client. Never raises on
    a single subscription failure — errors are logged and surfaced as counts."""
    subs = subscriptions if subscriptions is not None else load_subscriptions()
    results: dict[str, dict[str, int]] = {}
    with OTXPulseClient(api_key) as client:
        for sub in subs:
            try:
                counts = pull_subscription(client, sub, session)
            except Exception as exc:
                logger.warning("otx_pulse_pull_failed", subscription=sub.name, exc=str(exc))
                counts = {"added": 0, "skipped": 0, "updated": 0, "filtered": 0, "error": 1}
            record_last_run(session, sub, counts)
            results[sub.name] = counts
        session.commit()
    return results
