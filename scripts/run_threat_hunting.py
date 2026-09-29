#!/usr/bin/env python3
"""Run automated threat hunting with Feedly.

This script runs the daily automated threat hunting workflow:
1. Collects fresh threat intelligence from Feedly
2. Extracts IOCs with context (malware, actors, CVEs, TTPs)
3. Runs automated checks against threat-hunting criteria
4. Generates prioritized threat list for analysts

Based on: https://feedly.com/customers/posts/automating-threat-hunting
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scry.feedly.threat_hunting import ThreatHuntingEngine

from scry.logging import get_logger

logger = get_logger("run_threat_hunting")


def main():
    """Run automated threat hunting."""
    print("=" * 80)
    print("AUTOMATED THREAT HUNTING WITH FEEDLY")
    print("=" * 80)
    print()

    engine = ThreatHuntingEngine()

    try:
        print("🔍 Running daily threat hunt...")
        print("   • Collecting fresh articles from Feedly")
        print("   • Extracting IOCs with context")
        print("   • Checking against threat-hunting criteria")
        print("   • Generating prioritized threat list")
        print()

        # Run the hunt
        report = engine.run_daily_hunt()

        # Generate analyst report
        analyst_report = engine.generate_analyst_report(report)

        # Print report
        print(analyst_report)

        # Save to file
        report_file = Path("threat_hunting_report.txt")
        report_file.write_text(analyst_report)
        print(f"\n📄 Report saved to: {report_file.absolute()}")

        # Summary
        print("\n✅ Threat hunting complete!")
        print(f"   Total threats identified: {report.total_threats}")
        print(f"   Critical threats: {report.critical_threats}")

        if report.critical_threats > 0:
            print(f"\n⚠️  WARNING: {report.critical_threats} CRITICAL threats require IMMEDIATE action!")

        return 0

    except Exception as exc:
        logger.error("threat_hunting_failed", error=str(exc))
        print(f"\n❌ Error: {exc}")
        return 1

    finally:
        engine.close()


if __name__ == "__main__":
    sys.exit(main())
