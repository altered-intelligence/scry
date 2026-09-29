#!/usr/bin/env python3
"""Simple Feedly enrichment - enrich existing observables and print results."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import UTC, datetime

from scry.enrichment.feedly import FeedlyEnricher
from sqlalchemy import select

from scry.config import get_settings
from scry.db import session_scope
from scry.logging import get_logger
from scry.models import Observable

logger = get_logger("feedly_enrich_simple")


def main():
    """Run Feedly enrichment on observables."""
    settings = get_settings()

    if not settings.feedly_api_token:
        print("ERROR: Feedly API token not configured")
        return 1

    print("Starting Feedly enrichment...")
    print(f"API Token: {settings.feedly_api_token[:20]}...")

    enricher = FeedlyEnricher()

    try:
        with session_scope() as session:
            # Get observables without Feedly enrichment
            supported_types = ["domain", "ipv4", "ipv6", "sha256", "sha1", "md5"]

            observables = [
                obs
                for obs in session.execute(select(Observable).where(Observable.type.in_(supported_types)))
                .scalars()
                .all()
                if "feedly" not in (obs.enrichment or {})
            ][
                :50
            ]  # Limit to 50 for now

            print(f"\nFound {len(observables)} observables to enrich")

            enriched = 0
            skipped = 0
            errors = 0

            for idx, obs in enumerate(observables, 1):
                print(f"\n[{idx}/{len(observables)}] Processing: {obs.normalized_value[:50]}")

                try:
                    result = enricher.lookup(obs.normalized_value, obs.type)

                    if not result.ok:
                        print(f"  ❌ Error: {result.error}")
                        errors += 1
                        continue

                    if result.fields.get("not_found"):
                        print("  ⊘ Not found in Feedly")
                        skipped += 1
                        # Still mark as checked
                        if obs.enrichment is None:
                            obs.enrichment = {}
                        obs.enrichment["feedly_checked_at"] = datetime.now(UTC).isoformat()
                        obs.enrichment["feedly"] = {"not_found": True}
                        session.commit()
                        continue

                    # Update observable enrichment
                    if obs.enrichment is None:
                        obs.enrichment = {}
                    obs.enrichment["feedly"] = result.fields
                    obs.enrichment["feedly_checked_at"] = datetime.now(UTC).isoformat()

                    # Add tags
                    malware_families = result.fields.get("malware_families", [])
                    if malware_families:
                        print(f"  🦠 Malware: {', '.join(malware_families[:3])}")
                        for malware in malware_families[:5]:
                            tag = f"malware:{malware.lower()}"
                            if tag not in (obs.tags or []):
                                obs.tags = (obs.tags or []) + [tag]

                    threat_actors = result.fields.get("threat_actors", [])
                    if threat_actors:
                        print(f"  🎭 Actors: {', '.join(threat_actors[:3])}")
                        for actor in threat_actors[:3]:
                            tag = f"actor:{actor.lower()}"
                            if tag not in (obs.tags or []):
                                obs.tags = (obs.tags or []) + [tag]

                    severity = result.fields.get("severity")
                    if severity:
                        print(f"  ⚠️  Severity: {severity}")

                    article_count = result.fields.get("article_count", 0)
                    if article_count:
                        print(f"  📰 Articles: {article_count}")

                    enriched += 1
                    session.commit()
                    print("  ✅ Enriched successfully")

                except Exception as exc:
                    print(f"  ❌ Exception: {exc}")
                    errors += 1
                    session.rollback()

            print("\n=== Summary ===")
            print(f"✅ Enriched: {enriched}")
            print(f"⊘ Not found: {skipped}")
            print(f"❌ Errors: {errors}")

    finally:
        enricher.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
