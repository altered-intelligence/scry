#!/usr/bin/env python3
"""Export enriched Feedly data for Power BI and Azure Data Explorer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scry.feedly.analytics_export import AnalyticsExporter


def main():
    """Export analytics data."""
    print("=" * 80)
    print("EXPORTING ENRICHED DATA FOR ANALYTICS PLATFORMS")
    print("=" * 80)
    print()

    exporter = AnalyticsExporter()

    # Export in multiple formats
    formats = ["csv", "json"]

    for fmt in formats:
        print(f"\n📊 Exporting in {fmt.upper()} format...")
        exports = exporter.export_all(output_dir=f"analytics_exports/{fmt}", format=fmt)

        print(f"   ✅ Exported {len(exports)} datasets:")
        for name, path in exports.items():
            print(f"      • {name}: {path}")

    # Generate Power BI schema
    print("\n📋 Generating Power BI schema...")
    schema_path = exporter.generate_power_bi_schema("analytics_exports/powerbi_schema.json")
    print(f"   ✅ Schema: {schema_path}")

    print("\n" + "=" * 80)
    print("✅ Analytics export complete!")
    print("\nTo use with Power BI:")
    print("1. Open Power BI Desktop")
    print("2. Get Data → Text/CSV")
    print("3. Select files from: analytics_exports/csv/")
    print("4. Create relationships using the schema file")
    print("\nTo use with Azure Data Explorer:")
    print("1. Create tables in your Kusto cluster")
    print("2. Use .ingest inline command with JSON files")
    print("3. Query with KQL (Kusto Query Language)")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
