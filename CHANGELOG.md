# Changelog

All notable changes to Scry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
semantic versioning.

## [Unreleased]

### Added

- **Scheduled full-page fetch for RSS stubs.** `fetch_full_content` used to
  run only when someone called `POST /ingest/fetch-full`, so feed articles
  with a short or empty summary stayed short forever. The scheduled ingest
  now runs it right after collection and before extraction (bounded to
  `CTI_FULL_FETCH_LIMIT` articles per run, default 25; only articles
  ingested within `CTI_FULL_FETCH_MAX_AGE_HOURS`, default 72, so pruned HTML
  is not re-downloaded; disable with `CTI_FULL_FETCH_ENABLED=false`). Failed
  fetches are recorded in `source_fetches` and the URL backs off for
  `CTI_FULL_FETCH_RETRY_HOURS` (default 6); a page that fetches fine but is
  not longer than the stored text is marked done instead of being refetched
  every cycle.

### Security

- **Auth cookies are marked `Secure` over HTTPS.** The session, MFA-pending,
  passkey-pending, and first-run CSRF cookies are now set through one helper
  that adds the `Secure` attribute when the request arrived over HTTPS
  (including `X-Forwarded-Proto` behind a trusted proxy). New
  `CTI_COOKIE_SECURE` setting: `auto` (default), `true`, or `false`; plain
  `http://localhost` keeps working under `auto`. Behind a TLS-terminating
  proxy, run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy-ip>`
  or set `CTI_COOKIE_SECURE=true`.
- **`GET /api/ai/provider` now requires authentication.** It was exempt so
  the Search page could populate its picker, but it exposes configured base
  URLs, masked key tails, and connection-test errors to anyone who can reach
  the port. The Search page calls it with the session cookie, so signed-in
  users see no change; `/health` and `/api/ai/status` stay open. With only a
  master key configured and no user accounts, the browser picker needs an
  account (or `CTI_OPEN_ACCESS`) because the page cannot send the key.
- **`POST /sources` is admin-only** (when user accounts exist), matching
  `PATCH /sources/{id}` and the UI toggles: collection is global state, so a
  regular user could previously add feeds that every user's ingest would
  fetch. The master key and legacy zero-user open mode keep working.

### Fixed

- **Passwords over 72 bytes no longer crash.** bcrypt 5 raises `ValueError`
  for longer input, so `hash_password` failed with an HTTP 500 on first-run
  setup, profile password change, and admin user creation (and a traceback in
  `scry users create|reset-password|seed`), while `verify_password` swallowed
  the error and returned False. Passwords that fit keep their exact bcrypt
  hash, so every existing account is unaffected. Longer passphrases are
  pre-hashed (`bcrypt-sha256$` + bcrypt of `base64(sha256(password))`), so the
  whole password counts rather than only its first 72 bytes. Input is capped
  at 1,024 characters with a clear error on every entry point (web forms and
  CLI), and login attempts over the cap fail cleanly.
- **Full-content fetch hardening.** Candidates from disabled sources no
  longer consume the per-run limit (filtered in SQL), one fetcher serves the
  whole batch so the per-host rate limiter actually applies, and when a page
  parses to no text the raw HTML is no longer stored as the article text.
- **Single-URL ingest now parses the page.** `POST /ingest/url`, `scry
  ingest-url`, and a source whose URL is a single page stored the article
  with an empty title and empty text, so extraction found nothing and
  nothing ever re-parsed it (the second-pass full-content fetch only selects
  rows with `raw_html IS NULL`, which these never are). The page is now run
  through the article parser at ingest: title, text, author, language, and
  canonical URL are stored, the raw HTML is kept (capped like the feed
  path), and the article is queued for the extraction pipeline. Sources
  under the `metadata_only` policy keep metadata but never page content.
- **Feeds are recognised by their body, not only their content-type.** A
  feed served as `text/html` without an XML declaration was mistaken for an
  article page and stored as a title-less, empty "article" whose URL was the
  feed itself (four such rows exist in the real database).

## [0.15.2] — 2026-10-03

### Fixed

- **Relationship evidence no longer stores whole "sentences".** The
  relationship extractor used the sentence containing both endpoints as
  evidence and split sentences on punctuation, so punctuation-free inputs
  (pasted IOC spreadsheets, hunt workbooks) produced single "sentences" of
  hundreds of KB that were copied onto every relationship row — 1.16 GB of a
  1.3 GB real database, with only 73 distinct texts across 9,385 rows.
  Evidence is now windowed around the two endpoints (closest pair of
  occurrences, two fragments when they are far apart) and hard-capped at
  `MAX_EVIDENCE_CHARS` (400). Sentences that fit the cap are stored verbatim,
  so prose articles are unchanged; the pipeline applies the same cap at the
  persistence sink as a guard for any future extractor.

### Added

- **`scry prune-evidence [--max-chars N] [--dry-run] [--no-vacuum]`** —
  re-windows oversized `relationships.evidence_text` rows exactly as new
  extractions are stored (both endpoint labels kept), reports rows and bytes
  reclaimed, and VACUUMs SQLite to shrink the file. Idempotent.
- **Startup repair.** The migration path trims oversized relationship
  evidence automatically (one COUNT when nothing is oversized; never blocks
  startup). The file itself shrinks after `scry prune-evidence` (VACUUM).

Live-verified on the real database (backup first): 9,333 oversized rows
re-windowed (both endpoint labels visible in the trimmed evidence), the
`relationships` table 1,167 MB → 4.5 MB, the SQLite file 1,348 MB → 126 MB
after VACUUM, `PRAGMA integrity_check` ok, 812 tests green.

## [0.15.1] — 2026-10-03

### Added

- **FortiGuard personal feed keys** — FortiGuard Labs joins VirusTotal and
  AlienVault OTX on the Threat Feeds "My API keys" card: per-user
  Fernet-encrypted key with save / test / remove. The test performs an
  authenticated indicator lookup (200 = found, 404 = auth accepted — both
  report Connected; 401/403/429 reported as failures). Observable detail
  pages get a "Re-check FortiGuard now" live-lookup button and a FortiGuard
  verdict panel (web category / IOC category / confidence badge), and the
  enrichment sidebar shows FortiGuard's last-checked age.

### Changed

- **Bulk-import origins hidden from the Sources page** — one-time local
  imports (sources with `local://` URLs) are not recurring feeds: they no
  longer render on /ui/sources and can no longer be mistaken for collection
  sources, while the rows (and every article / observable extracted from
  them) stay in the database for data lineage.
- The Sources page counts now reflect visible collection sources only.

## [0.15.0] — 2026-10-03

### Added

- **FortiGuard Labs enrichment provider** — full FortiGuard IOC Research API
  v1.6 surface behind `scry/enrichment/fortiguard.py`: `FortiGuardClient`
  (threat-intel search, related indicators, country visit counts, user
  submissions + ticket status, URL/IP/Domain/File batch + atomic
  investigation endpoints including whois/ASN/geoip/AI summaries, outbreak
  tags/IOCs/telemetry) and a `FortiGuardEnricher` wired into the enrichment
  engine with domain/url/ipv4/ipv6/md5/sha1/sha256/email/onion support
  (onions looked up as URLs) and a 7-day refresh TTL
  (`enrichment_refresh_days_fortiguard`). Registered in the provider
  settings panel (Intel Feeds → Enrichment Providers) with the standard
  toggle + Fernet-encrypted key + test-button treatment. `scry fortiguard`
  CLI group with 17 subcommands. Onions are now also routed to the
  VirusTotal and OTX enrichers as URL lookups.
- **Scheduled enrichment pass** — `scripts/enrichment_runner.py`: a
  resumable, time-boxed external-enrichment sweep over the observable table
  (non-VT providers in one pass; VirusTotal in its own 4/min-paced pass
  under the 480/day quota), progress persisted per pass in
  `system_settings`, staleness markers skipping fresh records without
  burning quota, last-run stats recorded. New `scry/enrichment/schedule.py`
  module holds the `enrichment.schedule.*` settings; admins configure the
  pass on /admin → **Scheduled enrichment** (enabled toggle, provider
  checkboxes, per-pass time budgets) via the new
  `POST /admin/enrichment-schedule/save` route, with an audit entry per
  change. The runner exits immediately when disabled, so a system cron or
  scheduled agent job can invoke it unconditionally.

### Changed

- VirusTotal and OTX enricher type sets now include `onion`.

## [0.14.0] — 2026-10-03

### Added

- **raw_html retention pruning.** `Article.raw_html` — the dominant share of
  database size, only ever needed to re-parse an article — is now pruned for
  articles older than `raw_html_retention_days` (env
  `CTI_RAW_HTML_RETENTION_DAYS`, default 30; `0` = keep forever). Age is
  anchored on `ingested_at` (falling back to `published_at`); articles with
  neither are never pruned. Pruning nulls ONLY `raw_html`: the row,
  `extracted_text`, FTS/embedding indexes, and all derived data are kept
  (reprocessing works off `extracted_text`, so the `extractor_version="0"`
  backlog is unaffected), and a pruned article that later needs its HTML is
  re-fetched from its URL by `fetch_full_content` — that path already
  selects on `raw_html IS NULL` (regression-tested).
- **Weekly scheduler job** `raw_html_prune` (Sunday 04:47 UTC, clear of the
  :04/:34/:19/:49 ingest jobs and the HH:12 digest): logs `articles_pruned`
  + `bytes_reclaimed`, skips cleanly when retention is 0, never raises.
- **`scry prune-html [--days N] [--dry-run] [--no-vacuum]`** — manual runs;
  dry-run reports counts + reclaimable bytes without writing; real runs
  VACUUM (SQLite, best-effort) to shrink the database file.

### Changed

- **Settings:** the never-wired placeholder `retention_raw_html_days`
  (default 14, referenced nowhere) is replaced by `raw_html_retention_days`
  (default 30, env `CTI_RAW_HTML_RETENTION_DAYS`).

Live-verified on the real 445-article DB (backed up first): dry-run at the
30-day default truthfully reported 0 candidates (no HTML that old); a 1-day
horizon pruned 80 articles / 613,642 B, and VACUUM + checkpoint shrank the
file 7946K → 7268K. Embeddings (445), observables (746), and the semantic
top-5 are unchanged; authenticated article API readers return
`raw_html: None` with `extracted_text` intact.

## [0.13.0] — 2026-10-03

### Added

- **`CTI_SECRET_FILE` setting** — relocates the auto-generated Fernet key
  from its default next-to-the-package location. Required for
  container/installed deployments where site-packages is read-only; the
  Dockerfile sets it to `/app/data/.cti_secret`. An empty value falls back
  to the default.

### Changed

- **Docker hardening.** The image is now a multi-stage build: a `builder`
  stage installs the pinned dependency set into a virtualenv, and the
  `python:3.12-slim` runtime stage copies only that venv — no
  `build-essential`/`libpq-dev`, no pip caches, and zero runtime system
  packages (runtime deps are self-contained wheels; `psycopg[binary]`
  bundles libpq). The container runs as a dedicated non-root `scry` user
  (uid/gid 1000) with `/app` as the only writable tree, and gains a
  `HEALTHCHECK` probing `/health` via python urllib (curl removed).
  Dependencies are pinned by a new `requirements.lock` (exact versions;
  refresh recipe in `docs/installation.md`) instead of a floating
  `pip install .`. The unused `AS base` alias is gone; base image moved
  3.11 → 3.12. `.dockerignore` additionally excludes tests/, docs/, logs/,
  coverage artifacts, `.github/`, and all Markdown except README.md.
  Verified without a Docker daemon on the release machine — full container
  simulation (fresh venv installed from the lock only, booted from a clean
  directory: `/health` 200, UI rendered from the wheel, Fernet key written
  0600 at the override path) plus static compose/lock/`.dockerignore`
  checks; `docker build` on a daemon-equipped host remains the final check.
- **docker-compose** gains a `cti_data` named volume at `/app/data` on
  `api` and `scheduler`, persisting the relocated Fernet key across
  container re-creation (previously stored encrypted secrets silently
  became unreadable on rebuild). Postgres/redis services unchanged; the
  deliberate `CTI_OPEN_ACCESS=true` local-demo comment is kept.

## [0.12.0] — 2026-10-03

### Added

- **Persisted semantic embeddings.** Article vectors are now computed once
  and stored in a new `article_embeddings` table (384-dim float32 packed
  blobs, 1536 B/row) instead of being re-derived from full corpus text on
  every search. Each row carries a `content_hash` (md5 over the embedded
  text + dimension) so edits rewrite only rows that actually changed, and
  a stored `dim` auto-invalidates vectors if the algorithm dimension ever
  changes. Write-time sync hooks run at the same points as the FTS index
  (feed ingestion, OTX pulses, full-content fetch, pipeline redaction),
  and an idempotent batched startup migration backfills existing
  databases (SQLite; Postgres keeps the legacy live-embedding path plus
  the write hooks). Queries now embed only the query string, load stored
  vectors columnar (no ORM row materialization), and score with numpy
  when available (pure-Python fallback — numpy is not a base dependency);
  articles missing a vector are embedded on the fly and persisted
  (self-healing stragglers). Ranking is unchanged — parity with the
  legacy path is covered by regression tests.

### Performance

- **Semantic search no longer re-embeds the whole corpus per query.**
  Query-time work drops from O(N·text) CPU + O(N·dim) memory to one query
  embedding + one matrix multiply over stored vectors; ~2× faster
  end-to-end on the real 445-article DB (0.117s → 0.057s), with the gap
  widening as the corpus grows.

## [0.11.0] — 2026-10-03

### Added

- **Daily digest email job.** The scheduler can now generate the daily
  report and email it every morning at HH:12 local time (default 07:12).
  Off by default — new settings `CTI_DIGEST_EMAIL_ENABLED`,
  `CTI_DIGEST_EMAIL_TO`, `CTI_DIGEST_EMAIL_HOUR`; the job is only registered
  when enabled *and* addressed, skips with a clear log line when SMTP is not
  configured, and never raises into the scheduler. The message is multipart
  (plain text + `text/markdown` alternative of the same report —
  `send_mail` gained an optional `markdown_body`); subject:
  `Scry daily digest — YYYY-MM-DD (N articles, M high-risk)` (24 h window,
  high-risk = risk ≥ 70).
- **`scry scheduler install` / `uninstall` / `status` / `run`.** One-command
  launchd setup on macOS: writes
  `~/Library/LaunchAgents/com.scry.scheduler.plist` (idempotent —
  reports installed/updated/unchanged) running the current venv interpreter
  with `-m scry.scheduler`, `WorkingDirectory` at the repo, an absolute
  `CTI_DATABASE_URL` (the default relative SQLite path is anchored),
  `RunAtLoad` + `KeepAlive`, and logs under `logs/` (gitignored). Nothing is
  loaded into launchd unless `--load` is passed; `status` shows
  installed/loaded state and digest readiness. Linux systemd unit example in
  `docs/scheduling.md`.

## [0.10.0] — 2026-10-03

### Added

- **LLM idle-unload.** The embedded local model (llama.cpp, ~2 GB RSS) is
  now released after `CTI_AI_IDLE_UNLOAD_S` seconds without inference
  (default 900; `0` disables). A daemon reaper thread — started on load,
  exiting on unload, never lingering — performs the release; the next ask
  transparently reloads (~12s, same as the first load). Unload takes the
  inference lock first, so it can never fire mid-inference, and the idle
  timestamp is refreshed at the *end* of each inference so long answers
  don't count as idle. The model is also released on app shutdown via the
  FastAPI lifespan. `/api/ai/status` now reports `idle_seconds` and
  `idle_unload_s` alongside `model_loaded`.

## [0.9.0] — 2026-10-02

### Added

- **FTS5 full-text search.** On SQLite (the default backend) `/search`, the
  UI search box, MCP `scry_search`, and AI retrieval now run against SQLite
  FTS5 indexes instead of leading-wildcard LIKE scans: one FTS5 table per
  searchable object type (`articles_fts` over title/extracted_text/summary,
  `observables_fts`, `entities_fts` over canonical_name + aliases,
  `claims_fts` over claim/evidence text), `porter unicode61` tokenization,
  `bm25()` relevance ranking, and `snippet()` match excerpts.
  - Free-text queries are sanitized into quoted AND-joined MATCH terms, so
    operator characters (`OR`, `NEAR/`, parentheses, `*`, …) can never break
    a query or change its meaning; anything unsanitizable (and any
    `OperationalError` from the index) falls back to the legacy LIKE scan.
    Postgres and SQLite builds without FTS5 keep the LIKE path unchanged.
  - The startup migration creates the tables and backfills them idempotently
    (batched, orphan-purging) — existing databases are indexed on first boot
    (verified live: 445 articles / 746 observables / 2 entities / 38 claims
    indexed exactly, second boot a no-op).
  - Write paths keep the index in sync incrementally: feed ingestion, OTX
    pulse updates, full-content fetches, and pipeline extraction all
    upsert/delete FTS rows in the same commit flow as their content writes
    (best-effort — an indexing failure can never break ingestion).
  - The FTS tables are regular (content-owning) FTS5 tables by design:
    external-content tables corrupt ("database disk image is malformed")
    when a row is deleted/replaced after its content changed, which is
    exactly the reprocessing pattern here.
  - Entity alias search now works: aliases are indexed, so searching an
    alias (e.g. a group's alternative name) finds the entity.

### Performance

- Search no longer scans `articles.extracted_text` with leading-wildcard
  LIKE on every query; indexed MATCH + bm25 replaces the full-table scan,
  and AI retrieval (which issues one search per extracted keyword) benefits
  proportionally.

## [0.8.2] — 2026-10-02

### Security

- **Closed the open-by-default auth gap.** A fresh install (zero user
  accounts, no `CTI_API_KEY`) no longer serves anything unauthenticated:
  the app starts in **setup-required mode** — every UI route redirects to
  the first-run `/setup` page and every API route returns 403 until the
  first administrator is created (only `/setup`, `/login`, `/health`, and
  `/static` stay reachable). Once the account exists, normal auth applies
  and the mode can never return. The legacy zero-user open mode survives
  behind the explicit `CTI_OPEN_ACCESS=true` escape hatch (local-only
  bundles / MCP / automation; a loud startup warning is logged). A master
  `CTI_API_KEY` with zero users keeps its previous behavior. The
  `docker-compose.yml` bundle now sets `CTI_OPEN_ACCESS=true` explicitly
  with a comment spelling out the trade-off instead of silently shipping
  open.

## [0.8.1] — 2026-10-01

### Security

- **Method-aware API key auth + admin gate on provider config.** API key
  verification is now HTTP-method aware (read-only exemptions where intended,
  writes always require a key), and `PUT /api/ai/provider` is admin-gated.
  Provider config can no longer reuse a stored API key against a changed
  `base_url` — the key must be re-entered, closing a stored-key exfiltration
  path. Enrichment provider configuration and `PATCH /sources/{id}` are
  admin-gated, and the sources PATCH endpoint only accepts an explicit field
  allowlist (no mass assignment).
- **XSS escape.** User-controlled content rendered in the UI is escaped.
- **SSRF hardening in the fetcher.** Redirect targets are re-validated on
  every hop, DNS resolution fails closed (unresolvable/bogus answers are
  refused, not fetched), secrets are no longer propagated into redirect URLs,
  and response bodies are capped while streaming (decompression bombs no
  longer exhaust memory).
- **CSRF tokens on UI POST forms** (the three state-changing UI POSTs).
- **Serialized local-LLM inference** — concurrent asks no longer race the
  single embedded model instance.

### Fixed

- **JSON tag filters on SQLite.** `Column.contains([tag])` compiles to a LIKE
  pattern including the array brackets, so it only ever matched single-tag
  rows. A shared `scry.db.tag_filter` helper (quoted-tag LIKE with `%`/`_`
  escaping) now backs `/articles?tag=`, `/observables?tag=`, and the
  ransomware-topic alert trigger — multi-tagged articles match and fire
  alerts correctly.
- **Pipeline reprocessing is idempotent.** `process_article` first deletes
  the article's previously derived rows (observable/entity mentions, claims,
  relationships, ATT&CK mappings, and orphaned open claim reviews), and
  review routing skips creating a duplicate OPEN review for the same
  (item_type, item_id). Re-runs (`fetch-full`, OTX pulse updates,
  `scry extract`, extractor version bumps) no longer multiply derived rows.
- **`Observable.last_reported` never moves backwards** when an older article
  is re-ingested (max of existing/new, timezone-safe for SQLite's naive
  round-trip).
- **Feed ingest: one repeated URL no longer nukes the whole feed.** Duplicate
  URLs within a single feed are skipped via an in-loop seen set; previously
  the pending rows were invisible to the duplicate check and the single
  commit failed with IntegrityError, dropping every new article in the feed.
- **`POST /ingest/url` without `source_id` returns 200** instead of 500: a
  get-or-create "Manual" source (type `manual`, baseline confidence 50,
  `safe_public_web` policy) is attached to ad-hoc ingests.
- **Clusters no longer duplicate every run** — the previous set for the
  clustering method is replaced in the same transaction.
- **Conflicts no longer duplicate every run** — existing (claim_a, claim_b)
  pairs are loaded before detection. The same-attribution heuristic no longer
  treats shared sentence-opener stopwords ("The", "According", "Researchers",
  …) as actor agreement.
- **Alembic/runtime migration paths converge.** `alembic upgrade head`
  (0001_initial) now applies the same column ALTERs and index backfills as
  the app's startup migrations (`scry.migrations.apply_migrations`), and the
  migrations module docstring no longer claims alembic is absent. Migration
  application is table/column-aware so partial legacy databases migrate
  cleanly.
- **Alias resolution restricted to `threat_actor` and `malware_family`** —
  tools, campaigns, and other entity types pass through unchanged instead of
  being misresolved through the malware alias table.
- **Benign-infrastructure matching is boundary-safe** — `notamazonaws.com`
  no longer matches the `amazonaws.com` allowlist entry (exact or dot-suffix
  match only).
- **AI Search prompt budgeting.** History is trimmed oldest-first (keeping
  the newest exchange and user/assistant alternation) and source snippets are
  capped to a char budget sized for a 4096-token context (~4 chars/token,
  with headroom reserved for the system prompt and the answer). Long chats
  no longer fail with a permanent 502.
- **Pagination bounds.** `le=`/`ge=` caps on `/claims`, `/relationships`,
  `/alerts`, `/clusters`, `/conflicts`, `/cves`, `/jobs`,
  `/observables/search`, `/search`, `/reviews`, and offsets; `/entities`,
  `/threat-actors`, `/malware`, `/campaigns` now take a bounded `limit`
  instead of returning unbounded lists.
- **Backup/restore is WAL-aware** — backups checkpoint the WAL before
  archiving, and restores delete stale `-wal`/`-shm` sidecars so old rows
  can't be replayed over a restored database.
- **Housekeeping:** removed the duplicate `_check_owned` definition in
  `scry/api/chat.py`, dropped the unused `orjson` dependency, added a
  `.dockerignore`.

### Performance

- **SQLite runs in WAL mode with a 5 s busy timeout** (SQLite only;
  Postgres untouched), so the API, scheduler, and CLI share the database
  file without lock errors. Scheduler jobs were staggered (`ingest_all` at
  :04/:34, `otx_pulses` at :19/:49 UTC) and `_ingest_all_job` failures are
  caught and logged instead of killing the job.
- **New indexes:** `observables.risk_score`, `observables.status`,
  `cves.kev`, `articles.ingested_at`, `source_fetches.fetched_at` — declared
  in the models for fresh databases and backfilled for existing ones via
  idempotent `CREATE INDEX IF NOT EXISTS` migrations.
- **Faster test suite** (prior pass): cheap bcrypt rounds and shared
  fixtures cut the full run to well under a minute.

Known issues (deferred, not regressions): FTS5 migration, persisted semantic
embeddings, Dockerfile multi-stage rework, and LLM idle unload remain open.

## [0.8.0] — 2026-10-01

### Added

- **`scry backup` / `scry restore`** — one-command move of an install between
  machines (code travels via git; this moves the data). tar.gz archive with a
  `manifest.json` (version, table counts, sha256 checksums) containing the
  SQLite database, `.env`, `.cti_secret`, and `config/*.yaml`. `--full` adds
  `data/` and downloaded AI models; `--encrypt` Fernet-encrypts the archive
  using the install's existing `.cti_secret`. Restore validates manifest +
  checksums, blocks path-traversal entries, restores atomically, refuses to
  overwrite an existing database or accept a newer-version archive without
  `--force`, and prints a before/after table-count summary. Help text
  documents running with the server stopped.
- **EPSS enricher** — keyless FIRST.org EPSS for CVEs: populates `epss` +
  new `epss_percentile` / `epss_enriched_at` columns (startup auto-migration),
  batch queries (≤30 CVEs/request, 1 req/2 s), 7-day TTL refresh, oldest-first,
  capped per run (`CTI_EPSS_MAX_PER_RUN`, `CTI_EPSS_REFRESH_DAYS`). Runs in
  every batch enrichment via a new `epss` provider filter; CVE detail page
  shows score, percentile, and age. Live-verified: 100 CVEs enriched with real
  scores from api.first.org.
- **crt.sh passive-DNS / certificate-transparency enricher** — keyless
  subdomain discovery for domain observables from public CT logs (passive
  only — no active scanning; stays inside SECURITY.md boundaries). Distinct
  SAN count + up to 25 samples stored in the observable enrichment JSON,
  14-day TTL (`CTI_PASSIVE_DNS_REFRESH_DAYS`, `CTI_PASSIVE_DNS_MAX_PER_RUN`),
  one request per domain per run with a 2 s interval, empty-result sentinel
  so unlogged domains aren't re-queried until TTL, timeouts skip rather than
  fail. Observable detail page shows a "Certificate transparency" panel.
  New `passive_dns` provider filter. Note: real-data landing was unverifiable
  at release time because crt.sh itself was returning 502 — the error path
  was live-verified and the next scheduled run backfills automatically once
  the service recovers.

## [0.7.2] — 2026-10-01

### Fixed

- **Docs: corrected REST API paths.** The main REST API serves at root paths
  (`/articles`, `/observables`, `/ingest/*`, `/alerts`, `/exports/*`, …); only
  the AI routes (`/api/ai/*`), `/api/reports/brief`, and `/taxii2/*` carry a
  prefix. README references updated to match `docs/api-reference.md` (already
  correct). No code changes. An earlier e2e first-run verification surfaced
  the discrepancy.

## [0.7.1] — 2026-10-03

### Security

- **Removed hardcoded default admin credentials.** The repo no longer ships a
  default initial password or hardcoded seed usernames (previously
  `scry users seed` created two named admins from a password committed to the
  repo). Note: the old password remains visible in git history — rotate any
  deployment still using it.
- **First-run admin setup page.** While the users table is empty, `/login`
  points to a new CSRF-guarded `/setup` page ("Create first administrator
  account": username, password, confirm, optional email). The first account
  is created as role=admin with `must_change_password=false`, the installer is
  signed in immediately, and the page starts returning 404 the moment any
  account exists (also enforced on POST, and re-checked inside the
  transaction). The setup event is written to the audit log.
- **`scry users seed` now bootstraps a single admin safely.** New signature:
  `scry users seed --username NAME [--password PW] [--email EMAIL]`. Without
  `--password` a random one-time password is generated and printed to stdout
  exactly once (must be changed at first login). The command refuses to run
  once any user account exists.

## [0.7.0] — 2026-09-30

### Added

- **Sources management under Intel Feeds** — the Sources page moved under the
  Intel Feeds menu and now shows a per-source on/off checkbox for every
  configured source. Toggling is admin-only: standard users see greyed,
  disabled checkboxes reflecting current state with an "Only admin users can
  toggle sources on/off" hover hint, and only admins can POST
  `/ui/sources/{id}/toggle` (CSRF-guarded) to flip `Source.enabled`. Ingest
  already skips disabled sources via `registry.enabled_sources()`; collection
  is **global** — source toggles affect what everyone collects.
- **9 new vendor-blog sources** — Cisco Talos, SOCRadar, The DFIR Report,
  Securelist, Krebs on Security, SentinelOne Labs, Red Canary, Rapid7, and
  Huntress added to `config/sources.yaml` (`type: vendor_blog`, enabled by
  default), completing the requested 15 vendor blogs alongside the 6 already
  present (CrowdStrike, Fortinet, Unit42, Check Point, Google/Mandiant,
  Microsoft). Note: Talos and Rapid7 use the feed URLs their homepages declare
  after the originally guessed URLs 404'd; Talos's CDN may 403 non-browser
  fetch clients.
- **Collection window (last N days)** — ingest now collects only feed entries
  published within the last N days (default 1 = 24h) via the new
  `collection_window_days` SystemSetting, admin-configurable 1–7 days on /admin
  and displayed read-only on the Sources page. Entries without a published
  date are always kept; the window applies to new collection only — existing
  articles are untouched. Ingest results report a new `window_skipped` count.

### Fixed

- **yaml→DB sync no longer reverts runtime source toggles** —
  `SourceRegistry.sync_from_yaml` previously overwrote `Source.enabled` from
  yaml on every startup; it now keeps the DB value for existing sources (yaml
  `enabled` applies at source creation only), so admin toggles survive
  restarts.

## [0.6.0] — 2026-09-30

### Added

- **OTX pulse ingestion as a first-class source** — subscribe to AlienVault
  OTX pulses from `config/otx_pulses.yaml` (name, query, optional tags,
  `max_pulse_age_days` default 30, `limit` default 25). Pulled pulses are
  stored as Articles (`source: otx_pulse:<name>`) so the existing
  extraction/enrichment pipeline picks up their IOCs, with URL-based dedup
  making re-pulls idempotent. Trigger via `POST /api/ingest/otx-pulses`
  (optional subscription filter), `GET /api/ingest/otx-pulses/subscriptions`,
  `scry ingest otx-pulses`, the subscriptions panel on Threat Feeds, or the
  scheduled job alongside the existing ingest jobs. Scheduled pulls use the
  system OTX key; user-triggered pulls use the acting user's personal key;
  disabled entirely when no OTX key is configured anywhere.
- **Vendor-verdict alert escalation** — new AlertEngine trigger
  `vendor_confirmed_malicious`: VirusTotal malicious votes
  ≥ `CTI_VT_ESCALATE_MIN_DETECTIONS` (default 10) AND malicious ratio
  ≥ `CTI_VT_ESCALATE_MIN_RATIO` (default 0.5), GreyNoise classification
  matching `CTI_GN_ESCALATE_CLASSIFICATION` (default "malicious"), or
  AbuseIPDB score ≥ `CTI_ABUSEIPDB_ESCALATE_MIN_SCORE` (default 80).
  Confirmed observables get an alert (deduped once per observable+provider)
  plus a risk_score bump (default `CTI_ESCALATION_RISK_BUMP`, capped at 100)
  and a badge for the new trigger on the Alerts page.
- **Staleness-aware enrichment refresh** — per-provider refresh TTLs
  (`CTI_ENRICHMENT_REFRESH_DAYS_VIRUSTOTAL=7`, `..._OTX=14`,
  `..._ABUSEIPDB=7`, `..._GREYNOISE=3`). Batch enrichment now re-enriches
  only observables whose `{provider}_checked_at` marker is missing or older
  than the TTL (fresh ones counted as `fresh_skipped`), orders work
  oldest-first so quota goes to the stalest data, and reports
  `fresh_skipped`/`refreshed` counts. `force=true` on
  `POST /api/enrichment/run` ignores markers entirely. The UI shows
  per-provider "last enriched Xd ago" with per-provider Re-check on
  observable detail, "Re-enrich stale" / "Force re-enrich all"
  (confirm-guarded) buttons on the observables page, and fresh/stale
  coverage counts on /admin.

### Fixed

- **OTX pulse tag filtering** — tag matching is now case-insensitive, and a
  tag filter triggers a pulse-detail fetch (OTX search results omit pulse
  tags); the detail call uses a longer timeout with one retry on read
  timeout.
- **connector_settings migration** — existing databases missing the
  `api_key_encrypted` column on `connector_settings` are backfilled
  automatically at startup.
- **Example OTX subscription config** — relaxed the shipped example
  (dropped an over-strict tag filter that forced slow detail calls on every
  pull).

## [0.5.0] — 2026-09-30

### Added

- **User accounts** — bcrypt password hashes, DB-backed sessions (HttpOnly
  cookie, sliding 7-day expiry, revoke-anywhere "log out everywhere"), login
  throttling (5 failed attempts → 15-minute lockout), and a `scry users` CLI
  (create / list / promote / demote / reset-password / disable / seed).
  Email is required for all users.
- **Full auth options per user** — each account can authenticate with its
  password, **TOTP MFA** (Google Authenticator QR setup, verify-before-enable,
  10 one-time recovery codes shown once), or **WebAuthn passkeys** (register
  and rename on /profile, username-first login, satisfies MFA). The WebAuthn
  relying party is derived per-request from the Host header, so passkeys work
  on localhost today and on LAN/HTTPS later. Admins can force-disable a user's
  MFA.
- **Admin panel at /admin** — user management (create, edit role, disable,
  reset password, delete), application stats, a failed-login / lockout panel,
  session revocation, and an admin audit log.
- **/profile page** — display name, password change (with must-change
  enforcement at first login), email verification (6-digit PIN delivered via
  SMTP when configured, auto-verified otherwise), and **per-user scry API
  keys** (masked after creation, revocable, optional expiry, last-used
  tracking).
- **Admin SMTP configuration** — DB-stored SMTP server settings (password
  Fernet-encrypted) with a test button and env fallback, powering all email
  features; email verification and notifications bypass cleanly when unset.
- **Per-user privacy** — AI chat sessions are owner-scoped (visible only to
  their owner), and review/alert-ack actions are attributed to the acting
  user. Intel data itself stays shared.
- **API authentication** — once any user exists, `/api/*` and `/taxii2`
  require a session cookie, a per-user API key, or the master `CTI_API_KEY`;
  when no users exist the API stays legacy-open. Health and AI status/provider
  endpoints stay exempt.
- **Per-user VirusTotal/OTX keys on Threat Feeds** — personal feed keys with a
  visible-while-typing, masked-after-save input and a Test button
  (Connected/Failed badge); live verdict lookup on observable detail pages;
  bulk "enrich unenriched" using personal keys with quota awareness; enrichment
  coverage stats on /admin; and `scry feeds migrate-env-keys` to move existing
  env keys into user profiles. User-triggered lookups use the acting user's
  keys; background ingest/enrichment keeps using the system key.

## [0.4.0] — 2026-09-29

### Added

- **Optional API token auth** — set `CTI_API_KEY` and all `/api/*` and
  `/taxii2/*` routes require it via `X-API-Key` or `Authorization: Bearer`
  (constant-time compare, `401` + `WWW-Authenticate` challenge). When unset,
  everything stays open as before. `/health` and the AI status/provider
  endpoints stay exempt; the HTML UI (`/ui/*`) is never authenticated.
- **MCP server** — expose scry to AI clients (Claude Desktop, Cursor, any
  MCP host) over stdio: `pip install scry[mcp]`, then `scry mcp` or
  `python -m scry.mcp_server`. Six tools: `scry_health`, `scry_stats`,
  `scry_search`, `scry_observables`, `scry_alerts`, and `scry_ask`
  (grounded LLM Q&A, same pipeline as the Search page).
- **AI-synthesized briefs** — `POST /api/reports/brief?scope=daily|weekly`
  pipes the plain-text report through the active LLM provider into an
  executive summary (cached in-memory per scope/day). Also
  `scry reporting brief --scope daily|weekly` and a dashboard button.
- **Alert notification channels** — generic webhook (`CTI_WEBHOOK_URL`),
  email via SMTP (`CTI_ALERT_EMAIL_*`, `CTI_SMTP_*`), and macOS desktop
  notifications (`osascript`, no extra deps). `POST /api/alerts/test` sends
  a test message through every configured channel; a channel status panel
  on `/ui/alerts` shows state with a test button. `AlertEngine.evaluate()`
  now runs automatically at the end of every ingest run (delivery still
  gated by `CTI_ENABLE_OUTBOUND_ALERTS`; alerts are always recorded).
- **Ask conversation memory** — `POST /api/ai/ask` accepts an optional
  `session_id` and prepends the last N turns of history to the model
  context; assistant replies and sources are persisted. New sessions API
  under `/api/ai/sessions` (list, get, rename, delete), and the Search
  page gains a conversation sidebar with per-session history.
- **External IOC enrichment** — new AbuseIPDB (IP) and GreyNoise (IP)
  providers alongside VirusTotal and OTX; the VirusTotal daily quota is
  now enforced alongside per-minute rate limits. Per-provider enable
  toggles and API keys live in the database (Fernet-encrypted) with env
  fallback, managed from a new panel on `/ui/alerts`.
- **STIX 2.1 export + TAXII 2.1 server** — `POST /api/exports/stix21`
  emits spec-valid STIX 2.1 bundles (deterministic uuid5 ids): SDOs for
  threat actors, malware, campaigns, indicators, and relationships; SCOs
  for observables. A minimal read-only TAXII 2.1 server at `/taxii2/`
  offers server/api-root discovery plus two collections (`intel` and
  `articles`) with paginated object endpoints, protected by the same
  `CTI_API_KEY` when configured.

## [0.3.0] — 2026-09-29

### Added

- **Bring your own model** — AI Search now answers through a configurable
  LLM provider instead of only the bundled GGUF. A provider picker on
  `/ui/search` offers **Local GGUF (bundled)**, **Ollama**, **OpenAI**,
  **Anthropic**, **Google Gemini**, and **xAI**, with per-provider config
  (API key, base URL, default model). Keys are encrypted at rest (Fernet,
  key in `.cti_secret`) and only ever shown masked. Saving runs a connection
  test; exactly one provider is active at a time. Resolution order: the
  enabled provider → bundled GGUF → auto-detected Ollama. New
  `GET/PUT /api/ai/provider` endpoints and `resolve_ai_provider()` in the
  registry; the status pill names the active provider and model.

### Fixed

- **AI Search panel hidden by default**: `enable_ai_search` defaulted to
  `false`, so only the npm preview launcher showed the panel. It now
  defaults to **on** — a fresh install shows the panel with setup
  instructions until `scry ai-setup` downloads the model. Set
  `CTI_ENABLE_AI_SEARCH=false` to hide it.

## [0.2.0] — 2026-09-29

### Added

- **AI Search** (`/ui/search` + `/api/ai/*`): ask natural-language questions
  over collected intel and get grounded answers with `[n]` citations linking
  to the records used. Backed by a **self-contained local LLM** — GGUF via
  `llama-cpp-python` embedded in the Scry process (no server, no cloud, no
  API keys). New `LocalLlamaProvider` (lazy ~12s load on first question),
  `scry ai-setup` model download command (resume support), per-browser
  on-page enable/disable toggle, and settings `CTI_AI_SEARCH_MODEL_PATH` /
  `CTI_AI_SEARCH_MAX_TOKENS` / `CTI_AI_SEARCH_MAX_SOURCES` /
  `CTI_AI_SEARCH_TIMEOUT_S`. Off by default (`CTI_ENABLE_AI_SEARCH=true`);
  optional install extra `pip install -e ".[ai]"`. Default model
  Qwen2.5-1.5B-Instruct Q4_K_M (~1 GB disk, ~2 GB RAM) — fits 8 GB machines.

### Fixed

- **Ars Technica feed**: pointed the source at the working feed URL
  (`https://arstechnica.com/security/feed/`); the previous feed URL 404'd.
- **Bot-blocking sources (e.g. CISA)**: outbound HTTP now uses a browser-like
  User-Agent by default (new `default_user_agent` setting, overridable via
  `CTI_DEFAULT_USER_AGENT`) plus a full browser header set
  (`default_browser_headers()` in `scry/http.py`) — CISA's WAF fingerprints
  the header set, not just the UA, and previously returned 403.
- **Reddit / transient 429–503**: the fetcher now retries 429/503 up to
  3 attempts with exponential backoff (2s → 4s), honouring `Retry-After`
  (capped at 30s), and reports a clean error after the final attempt
  instead of failing on the first 429.

## [0.1.0] — 2026-09-28

Initial public release (formerly developed privately as "CTI Enrichment
Agent"; rebranded to **Scry** — *"Seeing threats before they arrive"* — while
keeping the `CTI_` env prefix and `cti.sqlite` default database for backwards
compatibility).

### Added

- **Ingestion**: RSS/Atom, HTML, and CISA KEV JSON collection from a
  YAML-driven source registry (`config/sources.yaml`) with per-source
  fail-closed collection policies and an SSRF guard.
- **Parsing**: trafilatura → readability → BeautifulSoup fallback pipeline,
  Unicode normalization, and pre-indexing secret redaction (AWS keys, JWTs,
  private keys, credential assignments).
- **Extraction**: IPv4/IPv6, domains, URLs, defanged variants, emails,
  hashes (MD5/SHA1/SHA256/SHA512/SSDEEP/TLSH), CVEs, ATT&CK techniques, ASNs,
  onion addresses, wallets, registry keys, named pipes, Telegram/Discord
  handles — with evidence text and confidence; dictionary-based threat actor /
  malware extraction with alias resolution; pattern-based claim extraction;
  relationship extraction; topic classifiers; pluggable (stubbed) LLM hook.
- **Enrichment**: infrastructure attributes (cloud/CDN/dynamic-DNS/paste-site/
  URL-shortener/benign-shared-infrastructure), URL roles, email lure hints,
  CVE/KEV details, ATT&CK mappings, prevalence/rarity; optional VirusTotal and
  AlienVault OTX connectors (cached, rate-limited, off without keys).
- **Scoring**: transparent source-reliability, multi-factor confidence, and
  contributor-based risk models; actionability levels; type-specific IOC
  lifecycle/decay.
- **Analysis**: article clustering (union-find over shared IOCs/entities),
  conflict detection between contradictory claims, dedup by URL + content
  hash.
- **Review workflow**: analyst review queue with routing rules, per-item
  dispositions, and bulk approve/reject actions in the UI.
- **Alerting**: KEV / Microsoft-exploited / high-risk / ransomware triggers;
  Slack/Teams/webhook channels off unless explicitly enabled.
- **Search**: full-text across articles/observables/entities/claims plus an
  offline hash-embedding semantic search.
- **Reports & exports**: daily/weekly Markdown reports; JSON, CSV, and
  STIX-like exports.
- **Web UI**: server-rendered dashboard (with "Collect now" and feed
  freshness), articles, observables, CVEs, entities, tags, sources, reviews,
  alerts, threat/ransomware intel feeds, and search pages; dark/light theme
  toggle with no-flash bootstrap; relative timestamps; flash messages.
- **API**: full REST API (`/docs` for OpenAPI) plus the `scry` CLI.
- **Docs**: installation, configuration, CLI, UI, API, and development guides
  under `docs/`; Apache-2.0 license.

### Security

- Defensive-use boundaries enforced in code: fail-closed collection policy
  engine, SSRF guard, secret redaction, no malware download, no credential
  collection, dark web disabled by default, outbound alerts off by default.
