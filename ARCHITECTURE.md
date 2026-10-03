# Architecture

## Goals

- Treat **claims, relationships, context, confidence, and provenance** as the actual intelligence — IOCs are evidence of claims, not the product itself.
- Be safe-by-default: every risky collection action requires an explicit opt-in.
- Be modular: every component (extractor, enricher, scorer, channel, connector) is replaceable without rewriting the pipeline.
- Be auditable: every extracted item carries `evidence_text`, `extraction_method`, `extractor_version`, `scoring_model_version`, and (where applicable) `explicit_or_inferred`.

## Module map

```
scry/
├── config.py                   # env + YAML loader, single source of truth
├── db.py                       # SQLAlchemy engine + session factory
├── logging.py                  # structlog setup
├── audit.py                    # write to audit_logs
│
├── ingestion/
│   ├── ssrf.py                 # SSRF guard (DNS-resolve, RFC1918, link-local, metadata, etc.)
│   ├── policy.py               # CollectionPolicyEngine — fail closed
│   ├── fetcher.py              # async httpx, rate limit, size cap, content-type gate
│   ├── source_registry.py      # YAML ↔ DB sync, lookup helpers
│   ├── rss.py                  # feedparser adapter
│   ├── cve_feed.py             # CISA KEV JSON parser
│   └── ingest_engine.py        # orchestrator (feed → article)
│
├── parsing/
│   ├── article_parser.py       # trafilatura → readability → bs4 fallback
│   ├── normalizer.py           # Unicode NFKC, whitespace, BOM
│   └── redactor.py             # AWS keys / JWTs / private keys / password/api_key assignments
│
├── extraction/
│   ├── defang.py               # refang / defang, looks_defanged
│   ├── ioc_extractor.py        # regex catalog + validators (FP guardrails)
│   ├── entity_extractor.py     # dictionary-based actor/malware lookup
│   ├── claim_extractor.py      # pattern-based claim extraction
│   ├── relationship_extractor.py # co-occurrence + verb cues
│   ├── classifiers/dispatch.py # topic tagging (microsoft, ransomware, wiper, …)
│   ├── llm/interface.py        # abstract LLM extractor
│   ├── llm/stub.py             # default stub (no network)
│   └── __init__.py (Extractor) # composes all the above
│
├── enrichment/
│   ├── base.py                 # BaseEnricher
│   ├── infrastructure.py       # TLD / cloud / dyndns / paste-site / shortener / benign flags
│   ├── url.py                  # scheme/host/path/query + suspected role
│   ├── email.py                # split user/domain + lure hints
│   ├── vulnerability.py        # CVE lookup (KEV / EPSS / MS surface)
│   ├── attack_mapping.py       # ATT&CK technique → name + tactic
│   ├── prevalence.py           # article + source counts, rarity score
│   └── engine.py               # EnrichmentEngine — dispatches per type
│
├── scoring/
│   ├── source_reliability.py   # SourceReliabilityProfile → 0–100
│   ├── confidence.py           # multi-factor breakdown
│   ├── risk.py                 # contributor list, actionability
│   └── lifecycle.py            # type-specific TTLs, decay
│
├── alias_resolution.py         # surface form → canonical, alias preservation
├── deduplication.py            # URL + content_hash dedup
├── clustering.py               # union-find by shared IOCs / entities
├── conflicts.py                # contradictory-claim detection
│
├── review/
│   ├── routing.py              # when to route to analyst review
│   └── queue.py                # list / update review items
│
├── alerting/
│   ├── engine.py               # KEV / Microsoft exploited / high-risk obs / ransomware
│   └── channels.py             # Slack / Teams (off unless explicitly enabled)
│
├── reporting/
│   ├── daily.py                # Executive summary, top stories, KEV, high-risk obs, review queue, collection gaps
│   └── weekly.py               # Trends, top actors / malware / sectors / regions
│
├── exports/
│   ├── json_export.py          # articles + observables JSON
│   ├── csv_export.py           # observables CSV
│   └── stix_like.py            # STIX-2.1-shaped bundle
│
├── connectors/
│   ├── base.py
│   ├── misp_stub.py            # dry-run only in MVP
│   └── opencti_stub.py
│
├── search/
│   ├── embeddings.py           # hash embedding + article_embeddings persistence (pack/unpack, content-hash sync, batched backfill)
│   ├── fts.py                  # FTS5 index layer: create/backfill/rebuild + incremental upsert/delete (SQLite)
│   ├── full_text.py            # FTS5 MATCH + bm25 + snippet, LIKE fallback (Postgres / no-FTS5)
│   └── semantic.py             # cosine over persisted vectors (numpy/pure-Python); legacy live-embedding fallback (Postgres)
│
├── api/
│   ├── deps.py
│   └── router.py               # every spec endpoint
│
├── ui/templates/               # base.html, dashboard.html, search.html, reviews.html
│
├── pipeline.py                 # Article → extract → enrich → score → persist → route
├── scheduler.py                # APScheduler recurring jobs
├── retention.py                # raw_html retention pruning (weekly job + `scry prune-html`)
├── cli.py                      # scry commands
└── main.py                     # FastAPI app + UI mount
```

## End-to-end data flow

```
                        ┌──────────────────────────┐
   YAML config ────────▶│  SourceRegistry          │
                        └──────────────┬───────────┘
                                       │
                                       ▼
                        ┌──────────────────────────┐
                        │  CollectionPolicyEngine  │  (fail-closed gates)
                        └──────────────┬───────────┘
                                       │
                                       ▼
                        ┌──────────────────────────┐
                        │  SafeFetcher (+ SSRF)    │
                        └──────────────┬───────────┘
                                       │
        ┌──────────────────────────────┼────────────────────────────┐
        │                              │                            │
        ▼                              ▼                            ▼
   RSS / Atom                     HTML pages                  JSON feeds (KEV)
        │                              │                            │
        └──────────────┬───────────────┘                            │
                       ▼                                            ▼
              ┌────────────────────┐                       ┌────────────────┐
              │  IngestionEngine   │                       │  CVE rows      │
              └────────┬───────────┘                       └────────────────┘
                       │
                       ▼
              ┌────────────────────┐
              │  parse + normalize │
              └────────┬───────────┘
                       │
                       ▼
              ┌────────────────────┐
              │  Redactor (secrets) │
              └────────┬───────────┘
                       │
                       ▼
              ┌────────────────────────────────────────────────────────────┐
              │  Extractor                                                  │
              │    IOC + Entity + Claim + Relationship + Classifier + LLM   │
              └────────────────────────────┬───────────────────────────────┘
                                           │
                                           ▼
              ┌────────────────────────────────────────────────────────────┐
              │  EnrichmentEngine (infrastructure / URL / email / CVE /     │
              │                    ATT&CK / prevalence)                     │
              └────────────────────────────┬───────────────────────────────┘
                                           │
                                           ▼
              ┌────────────────────────────────────────────────────────────┐
              │  Scoring (source reliability, confidence, risk, lifecycle)  │
              └────────────────────────────┬───────────────────────────────┘
                                           │
              ┌────────────────────────────┴───────────────────────────────┐
              ▼                                                            ▼
       Persistence                                                  ReviewRouter
       (observables / claims / entities / relationships /              │
        attack_mappings / mentions)                                    ▼
              │                                              AnalystReview rows
              ├────────▶ Clustering (shared IOCs / entities)
              ├────────▶ Conflicts (contradictory attribution)
              └────────▶ AlertEngine ────▶ (channels off unless explicitly enabled)
                                       └─▶ Reports (daily / weekly)
                                       └─▶ Exports (JSON / CSV / STIX-like)
                                       └─▶ Search (FT + semantic)
                                       └─▶ API + UI + CLI
```

## Pluggability

- **LLM**: `scry.extraction.llm.get_llm_extractor()` reads `CTI_LLM_PROVIDER` and returns an adapter implementing `LLMExtractor`. A real Anthropic adapter slots in alongside the existing stub.
- **Enrichers**: implement `BaseEnricher.enrich(value, context)` and register in `EnrichmentEngine`.
- **Connectors**: implement `BaseConnector.test_connection()` + `push(dry_run=True)`.
- **Search**: replace `embed()` in `scry/search/semantic.py` with a real model + pgvector query.
- **Detection generators**: write into the `detections` table; mark `generated=True`, `validated=False`.

## Data model overview

See [`DATA_MODEL.md`](./DATA_MODEL.md). 30+ tables, all SQLAlchemy 2.x, all timestamped, all versioned by extractor/scoring model.

## Reproducibility

Every persisted item records:

- `parser_version` (on articles)
- `extractor_version` (on articles / claims / relationships)
- `scoring_model_version` (on observables)
- `extraction_method` (`regex`, `dictionary`, `cooccurrence`, `llm`, …)
- `explicit_or_inferred` (on claims and relationships)

This means a future change to a model or extractor can be detected by comparing version columns — no silent regressions.
