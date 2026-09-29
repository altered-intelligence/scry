# CLI usage

Scry ships a Typer-based CLI installed as the `scry` console script
(`.venv/bin/scry` after `pip install -e ".[dev]"`). Run `scry --help` or
`scry <command> --help` for built-in help.

All commands operate on the database selected by `CTI_DATABASE_URL`
(SQLite by default).

## Database

### `scry init-db`

Create the schema and sync `config/sources.yaml` into the `sources` table
(idempotent upsert by source name).

```bash
scry init-db
```

## Ingestion

### `scry ingest-url URL [--source NAME]`

Fetch and process a single article URL end-to-end (fetch → parse → redact →
extract → enrich → score → persist). Prints a warning and stores nothing if
the collection policy blocks the fetch or the URL is a duplicate.

```bash
scry ingest-url https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-001
scry ingest-url https://example.com/blog/post --source "Test Vendor Blog"
```

### `scry ingest-source NAME`

Fetch and process one configured source by exact name, then run the pipeline
on its newly ingested articles. Prints a JSON summary
(`articles` / `cves` / `errors` / `blocked`).

```bash
scry ingest-source "CISA Advisories"
```

### `scry ingest-all`

Fetch and process **every enabled source**, then pipeline-process all new
articles. Prints the same JSON summary aggregated across sources.

```bash
scry ingest-all
```

## Reprocessing

### `scry extract ARTICLE_ID`

Reset an article's `extractor_version` and re-run the full extraction +
enrichment + scoring pipeline on it (e.g. after changing an extractor).

### `scry enrich OBSERVABLE_ID`

Re-run the enrichment engine on one observable and print the resulting
enrichment fields as JSON.

## Search

### `scry search QUERY [--limit N]`

Full-text search across articles, observables, entities, and claims
(default limit 20). Prints a table of type / title / snippet.

```bash
scry search "ransomware" --limit 10
```

### `scry semantic-search QUERY [--limit N]`

Semantic search over articles using the built-in offline hash embedding.
Prints score / type / title.

```bash
scry semantic-search "Microsoft RCE exploited in the wild"
```

## Reports

### `scry report daily [--since-hours N]`

Print the daily Markdown report (executive summary, top stories, KEV updates,
high-risk observables, review queue digest, collection gaps). Default window:
last 24 hours.

### `scry report weekly`

Print the weekly Markdown report (trends; top actors / malware / sectors /
regions).

## Sources

### `scry sources list`

Table of all registered sources: id, name, type, enabled, collection policy,
tags.

### `scry sources test`

Dry-run the collection policy engine and SSRF guard for every enabled
source — no fetching. Prints source / policy / allowed / ssrf / reason.

## Review queue & alerts

### `scry reviews list`

Table of open analyst reviews (id, item, reason, confidence, recommended
action; up to 100).

### `scry alerts list`

Table of the 100 most recent alerts (id, trigger, severity, title).

## Lifecycle

### `scry decay run`

Apply IOC decay: expire indicators past their type-specific TTL and refresh
last-seen ones. Prints `{"expired": …, "refreshed": …}`.

## Diagnostics

### `scry stats`

JSON object with row counts for sources, articles, observables, CVEs, alerts,
and open reviews.

---

See also: [ui-guide.md](./ui-guide.md) for the web interface and
[api-reference.md](./api-reference.md) for the REST API equivalents.
