"""APScheduler-based recurring task scheduler.

Default schedule (UTC, staggered so the two ingest jobs never collide):
  ingest-all       every 30 min at :04/:34
  otx-pulses       every 30 min at :19/:49
  decay            daily
  alert evaluation every 15 min
  cluster refresh  hourly
  digest email     daily at HH:12 LOCAL time (only when
                   digest_email_enabled + digest_email_to are set)
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import func, select

from scry.alerting import AlertEngine
from scry.clustering import cluster_articles
from scry.config import get_settings
from scry.db import session_scope
from scry.ingestion import IngestionEngine
from scry.ingestion.otx_pulses import load_subscriptions, pull_all, resolve_key
from scry.logging import configure_logging, get_logger
from scry.mail import send_mail, smtp_configured
from scry.models import Article, Observable
from scry.pipeline import CTIPipeline
from scry.reporting import generate_daily_report
from scry.scoring.lifecycle import LifecycleEngine

logger = get_logger("scheduler")

HIGH_RISK_THRESHOLD = 70  # risk_score at/above this counts as "high-risk" in the digest subject


def _ingest_all_job() -> None:
    """Scheduled full ingest. Errors are logged, never raised — a failing
    source or transient DB lock must not kill the scheduler thread."""

    async def _run():
        with session_scope() as session:
            res = await IngestionEngine(session).ingest_all()
            pipeline = CTIPipeline(session)
            for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
                pipeline.process_article(art)
            logger.info("scheduler_ingest_done", result=res)

    try:
        asyncio.run(_run())
    except Exception as exc:
        logger.exception("scheduler_ingest_failed", exc=str(exc))


def _decay_job() -> None:
    with session_scope() as session:
        res = LifecycleEngine(session).apply_decay()
        logger.info("scheduler_decay_done", expired=res.expired, refreshed=res.refreshed)


def _alerts_job() -> None:
    with session_scope() as session:
        created = AlertEngine(session).evaluate()
        logger.info("scheduler_alerts_done", created=len(created))


def _cluster_job() -> None:
    with session_scope() as session:
        new = cluster_articles(session)
        logger.info("scheduler_cluster_done", created=len(new))


def _otx_pulses_job() -> None:
    """Scheduled OTX pulse pull (system key). Errors are logged, never raised."""
    try:
        with session_scope() as session:
            api_key, key_source = resolve_key(session, None)
            if not api_key:
                logger.info("otx_pulses_skipped", reason="no system OTX key")
                return
            results = pull_all(session, api_key=api_key, subscriptions=load_subscriptions())
            pipeline = CTIPipeline(session)
            processed = 0
            for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
                pipeline.process_article(art)
                processed += 1
            logger.info(
                "scheduler_otx_pulses_done", key_source=key_source, results=results, processed=processed
            )
    except Exception as exc:
        logger.exception("scheduler_otx_pulses_failed", exc=str(exc))


def _digest_job() -> None:
    """Daily digest: generate the daily report and email it via mail.py.

    Skips cleanly (and never raises) when disabled, unaddressed, or SMTP is
    not configured — the scheduler must stay up either way.
    """
    try:
        settings = get_settings()
        if not settings.digest_email_enabled:
            logger.info("digest_skipped", reason="disabled")
            return
        if not settings.digest_email_to:
            logger.info("digest_skipped", reason="digest_email_to empty")
            return
        with session_scope() as session:
            if not smtp_configured(session):
                logger.info("digest_skipped", reason="smtp not configured")
                return
            since = datetime.now(UTC) - timedelta(hours=24)
            articles = session.scalar(select(func.count(Article.id)).where(Article.ingested_at >= since)) or 0
            high_risk = (
                session.scalar(
                    select(func.count(Observable.id)).where(
                        Observable.last_seen >= since, Observable.risk_score >= HIGH_RISK_THRESHOLD
                    )
                )
                or 0
            )
            report = generate_daily_report(session)
            subject = (
                f"Scry daily digest — {datetime.now(UTC):%Y-%m-%d} "
                f"({articles} articles, {high_risk} high-risk)"
            )
            sent = send_mail(session, subject, report, to=settings.digest_email_to, markdown_body=report)
            logger.info(
                "digest_done", sent=sent, to=settings.digest_email_to, articles=articles, high_risk=high_risk
            )
    except Exception as exc:
        logger.exception("digest_failed", exc=str(exc))


def _build_scheduler(settings) -> BlockingScheduler:
    """Assemble the scheduler with all jobs (digest only when enabled)."""
    sched = BlockingScheduler(timezone="UTC")
    # Staggered wall-clock minutes so the two 30-min ingest jobs never fire
    # together and contend for the SQLite write lock.
    sched.add_job(_ingest_all_job, "cron", minute="4,34", id="ingest_all")
    sched.add_job(_otx_pulses_job, "cron", minute="19,49", id="otx_pulses")
    sched.add_job(_alerts_job, "interval", minutes=15, id="alerts")
    sched.add_job(_cluster_job, "interval", hours=1, id="cluster")
    sched.add_job(_decay_job, "interval", hours=24, id="decay")
    if settings.digest_email_enabled and settings.digest_email_to:
        hour = min(23, max(0, settings.digest_email_hour))  # clamp junk env values
        local_tz = datetime.now().astimezone().tzinfo  # digest is a local-time job
        sched.add_job(_digest_job, "cron", hour=hour, minute=12, id="digest_email", timezone=local_tz)
    return sched


def main() -> None:
    configure_logging()
    settings = get_settings()
    sched = _build_scheduler(settings)
    logger.info(
        "scheduler_started",
        digest_email=bool(settings.digest_email_enabled and settings.digest_email_to),
    )
    sched.start()


if __name__ == "__main__":
    main()
