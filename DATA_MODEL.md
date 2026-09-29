# Data model

Postgres (with pgvector available) is the production system of record. SQLite works for local dev and tests. Alembic builds the schema from SQLAlchemy metadata so the schema doesn't drift across 30+ tables.

## Core tables

| Table | Purpose | Notable fields |
| --- | --- | --- |
| `sources` | Source registry | `enabled`, `priority`, `baseline_confidence`, `collection_policy`, `independent`, `safety_mode` |
| `source_fetches` | Fetch history | `fetched_at`, `status_code`, `content_hash`, `bytes_downloaded`, `duration_ms`, `error` |
| `source_reliability_profiles` | Reliability metrics | `historical_accuracy`, `false_positive_rate`, `vendor_bias`, `sensationalism_score`, `is_aggregator` |
| `articles` | Ingested articles | `url` (unique), `canonical_url`, `content_hash`, `extracted_text`, `tags[]`, `pir_ids[]`, `parser_version`, `extractor_version` |
| `observables` | IOCs / indicators (unique on type + normalized_value) | `risk_score`, `actionability`, `status`, `expiration_date`, `ttl_days`, `enrichment` JSON, `scoring_model_version` |
| `observable_mentions` | Article ↔ observable join with evidence | `evidence_text`, `context_window`, `extraction_method`, `extraction_confidence` |
| `entities` | Threat actors, malware families, tools, campaigns (unique on type + canonical_name) | `aliases[]`, `attributes`, `confidence`, `tags[]` |
| `entity_mentions` | Article ↔ entity join | `evidence_text`, `extraction_method`, `extraction_confidence` |
| `claims` | First-class claim objects | `claim_type`, `evidence_text`, `explicit_or_inferred`, `review_status`, `needs_review`, `extractor_version` |
| `relationships` | Typed links | `source_type/id`, `target_type/id`, `relationship_type`, `evidence_text`, `explicit_or_inferred` |
| `cves` | CVE records | `kev`, `exploited_in_the_wild`, `ransomware_associated`, `is_microsoft`, `cvss_v3/v4`, `epss`, `references[]` |
| `malware_families` | Malware family records | `aliases[]`, `malware_type`, `capabilities[]`, `c2_protocol`, `confidence` |
| `threat_actors` | Actor records | `aliases[]`, `suspected_origin`, `motivation[]`, `attribution_confidence` |
| `campaigns` | Named campaigns | `timeframe_start/end`, `target_sectors[]`, `objective`, `confidence` |
| `attack_mappings` | ATT&CK technique mappings | `parent_type/id`, `technique_id`, `tactic`, `confidence`, `explicit_or_inferred` |
| `detections` | Sigma / YARA / KQL etc. | `rule_type`, `body`, `generated`, `validated`, `required_telemetry[]` |
| `analyst_reviews` | Review queue | `item_type/id`, `reason`, `status`, `disposition`, `analyst`, `correction` JSON |
| `conflicts` | Contradictory claims | `claim_a_id`, `claim_b_id`, `conflict_type`, `recommended_review_reason` |
| `alerts` | Generated alerts | `trigger`, `severity`, `dedup_key`, `delivered`, `related` JSON |
| `clusters` | Article / infra clusters | `kind`, `method`, `members` JSON |
| `audit_logs` | Audit trail | `actor`, `action`, `target_type/id`, `detail` JSON |
| `jobs` | Background jobs | `kind`, `status`, `payload`, `result`, `error` |

## Reproducibility columns

- Articles: `parser_version`, `extractor_version`
- Observables: `scoring_model_version`
- Claims & relationships: `extractor_version`, `explicit_or_inferred`, `extraction_method`
- Detections: `generated`, `validated`

## Why no STIX-strict schema

We keep the model loosely STIX-aligned but pragmatic. `scry/exports/stix_like.py` produces a STIX-2.1-shaped bundle for downstream STIX-strict tools to normalize.
