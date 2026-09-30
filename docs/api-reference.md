# API reference

REST API implemented in `scry/api/router.py` (FastAPI). Interactive OpenAPI
docs are available at `/docs` on a running instance. All endpoints are
JSON unless noted. List endpoints return arrays of the response model named
in `scry/schemas/`.

## System

| Method | Path | Params | Returns |
| --- | --- | --- | --- |
| GET | `/health` | — | `{"status": "ok"}` |
| GET | `/stats` | — | Row counts for all core tables (dict) |
| GET | `/trending` | `hours` (24) | Trending items over the window |
| GET | `/jobs` | `limit` (50) | Recent job rows |

## Sources

| Method | Path | Params / body | Returns |
| --- | --- | --- | --- |
| GET | `/sources` | — | `list[SourceOut]` |
| POST | `/sources` | `SourceIn` JSON body | `SourceOut` |
| GET | `/sources/{source_id}` | — | `SourceOut` (404 if missing) |
| PATCH | `/sources/{source_id}` | partial JSON body | `SourceOut` |
| GET | `/sources/{source_id}/reliability` | — | SourceReliabilityProfile data |

`SourceIn`: `name`, `type`, `url`, `feed?`, `enabled` (false),
`priority` ("medium"), `baseline_confidence` (60),
`collection_policy` ("safe_public_web"), plus optional registry fields.

## Ingestion & enrichment

| Method | Path | Params / body | Returns |
| --- | --- | --- | --- |
| POST | `/ingest/url` | JSON `{"url": …, "source_id"?}` | ingested article info (blocked/duplicate → null-ish) |
| POST | `/ingest/source/{source_id}` | — | ingest summary dict |
| POST | `/ingest/run` | — | ingest-all summary (`articles`, `cves`, `errors`, `blocked`) + pipeline reprocess |
| POST | `/ingest/fetch-full` | `limit` (50, ≤200) | second-pass full-HTML fetch + pipeline counts |
| POST | `/enrichment/run` | `limit` (200, ≤2000), `providers` (repeatable, default all enabled+keyed) | per-provider enrichment counts, `skipped` reasons |
| GET | `/enrichment/providers` | — | VT/OTX/AbuseIPDB/GreyNoise state (masked key, enabled, source) |
| PUT | `/enrichment/providers` | JSON `{"provider", "enabled", "api_key"?, "clear_api_key"?}` | updated provider entry (key encrypted at rest) |

## Intelligence objects

| Method | Path | Params | Returns |
| --- | --- | --- | --- |
| GET | `/articles` | `limit` (50, ≤500), `offset`, `tag` | `list[ArticleSummary]` |
| GET | `/articles/{article_id}` | — | `ArticleOut` |
| GET | `/observables` | `type`, `min_risk`, `tag`, `status`, `limit` (100, ≤1000), `offset` | `list[ObservableOut]` |
| GET | `/observables/search` | `q` (required), `limit` (50) | `list[ObservableOut]` |
| GET | `/observables/{ob_id}` | — | `ObservableOut` |
| GET | `/entities` | `type`, | `list[EntityOut]` |
| GET | `/entities/{entity_id}` | — | `EntityOut` |
| GET | `/claims` | `claim_type`, `limit` (100) | `list[ClaimOut]` |
| GET | `/claims/{claim_id}` | — | `ClaimOut` |
| GET | `/relationships` | `limit` (100) | `list[RelationshipOut]` |
| GET | `/cves` | `only_kev`, `limit` (100) | CVE rows |
| GET | `/cves/{cve_id}` | — | CVE detail |
| GET | `/threat-actors` | — | threat-actor entities |
| GET | `/malware` | — | malware-family entities |
| GET | `/campaigns` | — | campaign entities |

## Search

| Method | Path | Params / body | Returns |
| --- | --- | --- | --- |
| GET | `/search` | `q` (required), `limit` (50) | `list[SearchHit]` (full text) |
| POST | `/search/semantic` | `SemanticQuery`: `q`, `target` ("articles" \| "claims" \| "campaigns"), `limit` (20, ≤200) | `list[SearchHit]` |

## Alerts, clustering, conflicts

| Method | Path | Params | Returns |
| --- | --- | --- | --- |
| GET | `/alerts` | `limit` (100) | alert rows |
| POST | `/alerts/run` | — | evaluate alert triggers |
| GET | `/clusters` | `limit` (100) | article clusters |
| POST | `/clusters/run` | — | recompute clustering |
| GET | `/conflicts` | `limit` (100) | detected conflicts |
| POST | `/conflicts/run` | — | re-run conflict detection |
| GET | `/watchlists` | — | watchlists from `config/watchlists.yaml` |
| GET | `/pirs` | — | PIRs from `config/pirs.yaml` |

## Review queue

| Method | Path | Params / body | Returns |
| --- | --- | --- | --- |
| GET | `/reviews` | `limit` (100), `offset` | `list[ReviewItemOut]` |
| PATCH | `/reviews/{review_id}` | `ReviewUpdate`: `status?`, `disposition?`, `analyst?`, `comments?`, `correction?` | `ReviewItemOut` |

## Reports, exports, lifecycle

| Method | Path | Params | Returns |
| --- | --- | --- | --- |
| GET | `/reports/daily` | — | Markdown (text/plain) |
| GET | `/reports/weekly` | — | Markdown (text/plain) |
| POST | `/exports/json` | — | articles + observables JSON (text/plain) |
| POST | `/exports/csv` | — | observables CSV (text/plain) |
| POST | `/exports/stix-like` | — | STIX-2.1-shaped bundle (text/plain) |
| POST | `/decay/run` | — | `{"expired": n, "refreshed": n}` |

## Intel feeds

| Method | Path | Params | Returns |
| --- | --- | --- | --- |
| GET | `/intel-feeds/threat-feeds` | `q`, `category`, `network`, `country`, `threat_actor`, `sort` (`date_desc` default), `limit` (100, ≤1000), `offset` | threat-feed items |
| GET | `/intel-feeds/threat-feeds/stats` | — | totals + breakdowns |
| GET | `/intel-feeds/threat-feeds/{item_id}` | — | single item |
| GET | `/intel-feeds/ransomware-feeds` | `q`, `group`, `country`, `industry`, `sort` (`discovered_desc` default), `limit` (50, ≤500), `offset` | ransomware-feed items |
| GET | `/intel-feeds/ransomware-feeds/stats` | — | totals + breakdowns |
| GET | `/intel-feeds/ransomware-feeds/{item_id}` | — | single item |

## UI form endpoints (browser-oriented, 303 redirects)

These live in `scry/main.py` and serve the HTML UI; they redirect with
`?flash=…` query parameters rather than returning JSON:

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/ui/ingest/run` | Same ingestion path as `POST /ingest/run`, then redirect to `/` |
| POST | `/ui/reviews/bulk` | Bulk approve/reject open reviews (`review_ids[]`, `action`) |
| POST | `/ui/reviews/{review_id}` | Per-review disposition form save |

---

Back to [README](../README.md) · [usage-cli.md](./usage-cli.md)
