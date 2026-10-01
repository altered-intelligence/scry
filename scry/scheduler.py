"""APScheduler-based recurring task scheduler.

Default schedule:
  ingest-all       every 30 min
  decay            daily
  alert evaluation every 15 min
  cluster refresh  hourly
"""

from __future__ import annotations

import asyncio

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import select

from scry.alerting import AlertEngine
from scry.clustering import cluster_articles
from scry.db import session_scope
from scry.ingestion import IngestionEngine
from scry.ingestion.otx_pulses import load_subscriptions, pull_all, resolve_key
from scry.logging import configure_logging, get_logger
from scry.models import Article
from scry.pipeline import CTIPipeline
from scry.scoring.lifecycle import LifecycleEngine

logger = get_logger("scheduler")


def _ingest_all_job() -> None:
    async def _run():
        with session_scope() as session:
            res = await IngestionEngine(session).ingest_all()
            pipeline = CTIPipeline(session)
            for art in session.scalars(select(Article).where(Article.extractor_version == "0")):
                pipeline.process_article(art)
            logger.info("scheduler_ingest_done", result=res)

    asyncio.run(_run())


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


def main() -> None:
    configure_logging()
    sched = BlockingScheduler(timezone="UTC")
    sched.add_job(_ingest_all_job, "interval", minutes=30, id="ingest_all")
    sched.add_job(_otx_pulses_job, "interval", minutes=30, id="otx_pulses")
    sched.add_job(_alerts_job, "interval", minutes=15, id="alerts")
    sched.add_job(_cluster_job, "interval", hours=1, id="cluster")
    sched.add_job(_decay_job, "interval", hours=24, id="decay")
    logger.info("scheduler_started")
    sched.start()


if __name__ == "__main__":
    main()
