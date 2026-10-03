#!/usr/bin/env python3
"""Scheduled external enrichment pass for scry (v0.15.0).

Runs the configured external providers (see /admin → Scheduled enrichment)
over the observable table in resumable, time-boxed chunks:

    python scripts/enrichment_runner.py               # one full pass per config
    python scripts/enrichment_runner.py --providers otx fortiguard --budget-seconds 240
    python scripts/enrichment_runner.py --ignore-db-config --providers otx

Behaviour:
- Reads ``enrichment.schedule.*`` settings from the DB. When the schedule
  is disabled the pass exits immediately (exit code 0) unless
  ``--ignore-db-config`` is given.
- Non-VT providers run together in one pass (budget: ``otx_budget_seconds``);
  VirusTotal runs in its own pass (budget: ``vt_budget_seconds``) because its
  per-minute pacing (4/min) is far slower. GreyNoise/AbuseIPDB join the
  non-VT pass when configured with an API key.
- Progress persists per pass in ``system_settings`` so interrupted passes
  resume where they left off; provider staleness markers make already-fresh
  records skip without network calls.
- Per-provider tallies and any record-level errors are printed and recorded
  in ``enrichment.schedule.last_run``.

Run from the repo root with the project venv active:
    .venv/bin/python scripts/enrichment_runner.py
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sqlalchemy import select  # noqa: E402

from scry.db import session_scope  # noqa: E402
from scry.enrichment import EnrichmentEngine  # noqa: E402
from scry.enrichment.schedule import (  # noqa: E402
    get_progress,
    get_schedule,
    record_last_run,
    set_progress,
)
from scry.models import Observable  # noqa: E402

CHUNK = 100  # records per transaction (smaller when VT is in the pass)
VT_CHUNK = 25  # VT paces at vt_rate_per_min; keep commits frequent


def run_pass(providers: list[str], budget_seconds: int, tag: str) -> dict:
    """One resumable pass over the observable table for ``providers``."""
    t0 = time.time()
    start_from = 0
    with session_scope() as s:
        start_from = get_progress(s, tag)
    last_id = start_from
    records = fresh_skips = errors = 0
    chunk = VT_CHUNK if "virustotal" in providers else CHUNK

    while time.time() - t0 < budget_seconds:
        with session_scope() as s:
            rows = s.scalars(
                select(Observable).where(Observable.id > last_id).order_by(Observable.id).limit(chunk)
            ).all()
            if not rows:
                with session_scope() as s2:
                    set_progress(s2, tag, 0)  # pass complete; next run starts fresh
                return {
                    "pass": tag,
                    "providers": providers,
                    "complete": True,
                    "records": records,
                    "fresh_skipped": fresh_skips,
                    "errors": errors,
                    "seconds": round(time.time() - t0),
                }
            engine = EnrichmentEngine(s)
            for ob in rows:
                try:
                    res = engine.enrich_observable_external(ob, providers=providers, force=False)
                    fresh_skips += len(res.fresh_skipped)
                    records += 1
                except Exception as exc:  # single-record failure must not kill the pass
                    errors += 1
                    print(f"  ! id={ob.id} {ob.type} {ob.normalized_value[:60]!r}: {exc}", flush=True)
                last_id = ob.id
            s.commit()
        with session_scope() as s:
            set_progress(s, tag, last_id)
        print(f"  [{tag}] committed through id={last_id} ({time.time()-t0:.0f}s)", flush=True)

    return {
        "pass": tag,
        "providers": providers,
        "complete": False,
        "records": records,
        "fresh_skipped": fresh_skips,
        "errors": errors,
        "seconds": round(time.time() - t0),
        "resume_at_id": last_id,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--providers", nargs="+", default=None, help="Override the configured provider list for this run."
    )
    ap.add_argument(
        "--budget-seconds", type=int, default=None, help="Override the per-pass time budget for this run."
    )
    ap.add_argument(
        "--ignore-db-config",
        action="store_true",
        help="Run even when the schedule is disabled, and ignore stored budgets.",
    )
    args = ap.parse_args()

    with session_scope() as s:
        sched = get_schedule(s)

    if not sched.enabled and not args.ignore_db_config:
        print("Scheduled enrichment is disabled (admin → Scheduled enrichment). Nothing to do.")
        return

    providers = args.providers or sched.providers
    if not providers:
        print("No providers configured. Nothing to do.")
        return
    vt = [p for p in providers if p == "virustotal"]
    non_vt = [p for p in providers if p != "virustotal"]

    print(f"enrichment pass starting at {datetime.now(UTC).isoformat()} — providers: {providers}", flush=True)
    summaries = []
    if non_vt:
        budget = args.budget_seconds or sched.otx_budget_seconds
        print(f"non-VT pass ({', '.join(non_vt)}) budget={budget}s", flush=True)
        summaries.append(run_pass(non_vt, budget, "non_vt"))
    if vt:
        budget = args.budget_seconds or sched.vt_budget_seconds
        print(f"VirusTotal pass budget={budget}s", flush=True)
        summaries.append(run_pass(vt, budget, "virustotal"))

    with session_scope() as s:
        record_last_run(s, {"passes": summaries})

    print(json.dumps({"passes": summaries}, indent=2), flush=True)


if __name__ == "__main__":
    main()
