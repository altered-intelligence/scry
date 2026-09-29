#!/usr/bin/env python3
"""Run Feedly enrichment NOW - simple version that works with SQLite."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import UTC, datetime

from scry.enrichment.feedly import FeedlyEnricher
from sqlalchemy import select

from scry.config import get_settings
from scry.db import session_scope
from scry.models import Observable


def main():
    """Run Feedly enrichment."""
    settings = get_settings()

    if not settings.feedly_api_token:
        print("ERROR: Feedly API token not set")
        return 1

    print(f"✅ Feedly API configured: {settings.feedly_api_token[:20]}...")

    enricher = FeedlyEnricher()

    try:
        with session_scope() as session:
            # Get all observables (limit to 20 for demo)
            observables = session.execute(select(Observable).limit(20)).scalars().all()

            print(f"\n📊 Found {len(observables)} observables")
            print("=" * 60)

            enriched = 0
            for idx, obs in enumerate(observables, 1):
                # Skip if already has Feedly data
                if obs.enrichment and "feedly" in obs.enrichment:
                    continue

                print(f"\n[{idx}] {obs.type}: {obs.normalized_value[:60]}")

                try:
                    result = enricher.lookup(obs.normalized_value, obs.type)

                    if not result.ok:
                        print(f"   ❌ {result.error}")
                        continue

                    if result.fields.get("not_found"):
                        print("   ⊘ Not in Feedly")
                        continue

                    # Update
                    if obs.enrichment is None:
                        obs.enrichment = {}
                    obs.enrichment["feedly"] = result.fields
                    obs.enrichment["feedly_checked_at"] = datetime.now(UTC).isoformat()

                    # Show what we found
                    malware = result.fields.get("malware_families", [])
                    if malware:
                        print(f"   🦠 Malware: {', '.join(malware[:3])}")

                    actors = result.fields.get("threat_actors", [])
                    if actors:
                        print(f"   🎭 Actors: {', '.join(actors[:2])}")

                    articles = result.fields.get("article_count", 0)
                    if articles:
                        print(f"   📰 {articles} articles")

                    enriched += 1
                    session.commit()
                    print("   ✅ Enriched!")

                except Exception as exc:
                    print(f"   ❌ Exception: {exc}")
                    session.rollback()

            print(f"\n{'='*60}")
            print(f"✅ Enriched {enriched} observables with Feedly intelligence")

    finally:
        enricher.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
