# Scry — Project Handbook & AI Handoff Document

**Version:** 0.16.0 · **Repo:** https://github.com/altered-intelligence/scry · **License:** Apache-2.0
**Purpose of this document:** Explain what this project is, how it was built ("vibe coding" methodology), how it's organized, how GitHub is used as a backup, and — most importantly — provide a **master prompt** that lets any AI coding assistant (Claude Code, Codex, DeepSeek, Kimi, etc.) pick up development or recreate the project from scratch in any environment.

---

## 1. What Scry Is

Scry is a **self-hosted threat-intelligence platform** for defenders. It collects open-source intelligence (OSINT), extracts structured intelligence from it (IOCs, threat actors, malware, claims, relationships), enriches and scores it, and makes it searchable and actionable through a web UI, a REST API, an MCP server (for AI agent clients), and STIX 2.1 / TAXII 2.1 export.

**Design goals (in priority order):**

1. **Zero-infra by default** — runs on SQLite with a single `pip install`; Postgres/pgvector optional via Docker.
2. **Defensive-only, safe-by-default** — hard-coded safety boundaries (SSRF guard, fail-closed collection policies, secret redaction); risky capabilities ship disabled behind explicit `CTI_ENABLE_*` flags.
3. **Self-contained AI** — AI Search runs on a small bundled local GGUF model (~1 GB, no cloud), with a "bring your own model" provider system (Local GGUF / Ollama / OpenAI / Anthropic / Google / xAI).
4. **Multi-user with real auth** — bcrypt passwords, TOTP MFA, WebAuthn passkeys, admin panel, per-user API keys and per-user threat-feed keys.
5. **Standards-friendly output** — STIX 2.1 export, read-only TAXII 2.1 server, JSON/CSV/Markdown reports.
6. **Public-repo safe** — anyone can clone and run it; no secrets, credentials, or personal data ever live in the repo (see §6).

---

## 2. How It Was Built: The "Vibe Coding" Methodology

This project was built entirely through conversational AI sessions. The methodology that emerged — and that any future AI assistant should follow — is:

### 2.1 Feature tracks

Each minor version is planned as a **feature track**: an ordered list of small, independently-committed steps, each of which leaves the repo fully working. This allows pausing and resuming across sessions without breaking the build. The full historical tracks are preserved in `FEATURES.md` (every box checked) — they are the best examples of the convention.

Track conventions:

- Commit prefix `vX.Y.Z step N: <what>` — one logical step per commit.
- **Full test suite green before every commit.**
- Verify existing scaffolding before writing new code (stubs were often already in place).
- Don't touch runtime glue outside the repo (local dashboards, personal automations).
- Each track ends with a **Deploy/live-verify step** (run the server, click through the feature) and a **Release step**.

### 2.2 The release step (do this at the end of every track)

1. Bump version in `scry/main.py` (OpenAPI/version string) and `pyproject.toml`.
2. Add a `[X.Y.Z]` section to `CHANGELOG.md` (Keep a Changelog format: Added / Changed / Fixed / Security).
3. Update `README.md` ("What's new in X.Y.Z" section + feature bullets).
4. Commit as `Release vX.Y.Z: <headline>`.
5. Tag `vX.Y.Z`, push branch + tag.
6. Publish the GitHub release (`gh release create vX.Y.Z --title "scry vX.Y.Z" --notes <changelog section>`), marked Latest.
7. Verify: `gh release list`, confirm tag == `HEAD` == remote `HEAD`, working tree clean.

### 2.3 Build journal (what happened, version by version)

| Version | Date | What was built |
|---|---|---|
| **v0.1.0** | 2026-09-28 | Initial public release (rebranded from a private "CTI Enrichment Agent"; `CTI_` env prefix and `cti.sqlite` name kept for backward compatibility). YAML-driven ingestion (RSS/HTML/CISA KEV) with fail-closed policies + SSRF guard; parsing pipeline + secret redaction; extraction of 15+ IOC types, actors, malware, claims, relationships; structural enrichment; transparent scoring + IOC decay; clustering, conflict detection, dedup; review queue; alerting; full-text + offline semantic search; reports; JSON/CSV/STIX-like exports; web UI + REST API + CLI. |
| **v0.2.0** | 2026-09-29 | **AI Search** — grounded answers with `[n]` citations from a bundled local GGUF model (Qwen2.5-1.5B-Instruct Q4_K_M, ~1 GB) via `llama-cpp-python`, no cloud. `scry ai-setup` downloader. Feed fixes (Ars 404, CISA 403, retry/backoff with `Retry-After`). |
| **v0.3.0** | 2026-09-29 | **Bring your own model** — provider picker (Local GGUF / Ollama / OpenAI / Anthropic / Google Gemini / xAI); Fernet-encrypted keys at rest (key in `.cti_secret`); masked display; connection test. AI Search panel defaults on. |
| **v0.4.0** | 2026-09-29 | 7-step track: optional API token auth (`CTI_API_KEY`); **MCP server** (stdio, 6 tools); AI briefs; alert channels (webhook/SMTP/osascript, off by default); ask-conversation memory; external IOC enrichment (VT/OTX/AbuseIPDB/GreyNoise); **STIX 2.1 export** + read-only **TAXII 2.1** server. |
| **v0.5.0** | 2026-09-30 | 7-step track: **user accounts** (bcrypt, DB sessions, lockout throttling); **TOTP MFA** + **WebAuthn passkeys**; **/admin** panel; **/profile** (password change, email verification PIN, per-user API keys); SMTP config (DB-stored); per-user VT/OTX feed keys with Test button and live lookup; API auth once any user exists. Locked rule: scheduled jobs use the system key, user actions use the acting user's key. Seeded admins `alakhani` + `admin` (later removed — see v0.7.1). |
| **v0.6.0** | 2026-09-30 | 5-step track: **OTX pulse ingestion** as a first-class source (config-driven subscriptions); **vendor-verdict alert escalation** (auto risk bump when VT/GreyNoise/AbuseIPDB confirm malicious); **staleness-aware enrichment refresh** (per-provider TTLs, oldest-first, `force` override). |
| **v0.7.0** | 2026-09-30 | 4-step track: **Sources admin page** under Intel Feeds (per-source on/off checkboxes, admin-only, global collection); **15 vendor-blog sources** completed (Talos, SOCRadar, DFIR Report, Securelist, Krebs, SentinelOne Labs, Red Canary, Rapid7, Huntress added); **collection window** (last N days, 1–7, admin-only). |
| **v0.7.1** | 2026-10-01 | **Security**: removed hardcoded seed credentials; **first-run `/setup` page** (first account becomes admin, endpoint 404s once any user exists); `scry users seed --username NAME` (random one-time password, refuses if users exist); pre-commit + CI gitleaks secret scanning. |
| **v0.7.2** | 2026-10-01 | **Docs patch**: corrected REST API paths in README (main API serves at root paths like `/observables`; only `/api/ai/*`, `/api/reports/brief`, `/taxii2/*` carry a prefix) — surfaced by the fresh-clone e2e first-run verification. Also: black formatting applied, CI fixed (`.[dev,mcp]` install), CI/secret-scan README badges, green-CI release rule. |
| **v0.8.0** | 2026-10-01 | 3-step track: **`scry backup`/`scry restore`** (checksummed tar.gz archive of DB + `.env` + `.cti_secret` + config, `--full`/`--encrypt`, atomic restore, overwrite/version guards — live-verified round-trip); **EPSS enricher** (keyless FIRST.org EPSS → `epss_percentile`/`epss_enriched_at` on CVEs, 7d TTL — live-verified, 100 real CVEs); **crt.sh passive-DNS enricher** (keyless cert-transparency subdomains for domains, 14d TTL; real-data landing pending crt.sh outage, auto-retries). 654 tests. |
| **v0.8.1** | 2026-10-01 | **Hardening release** after a 3-sweep deep review (security/correctness/performance, 25 fixes, +41 regression tests): CRITICAL fix — unauthenticated `PUT /api/ai/provider` could exfiltrate stored LLM keys (now method-aware auth + admin gate + base_url re-key guard); stored-XSS escape in AI search; SSRF redirect-hop re-validation + DNS fail-closed; streamed fetch byte caps (gzip-bomb safe); no secrets in redirect URLs; sources PATCH allowlist + admin gates; CSRF on all UI POSTs; serialized local-LLM inference; JSON tag filters fixed on SQLite (ransomware alerts were silently broken); pipeline reprocess idempotency; SQLite WAL + busy_timeout; feed dup-URL guard; cluster/conflict run dedup; alembic↔migrations reconcile; prompt budgeting; pagination caps; new indexes; `.dockerignore`; test suite 195s→45s. 695 tests. |
| **v0.8.2** | 2026-10-02 | **First-run setup required** — zero users + no API key no longer serves UI/API unauthenticated: redirects to `/setup` (setup mode can never return once an admin exists). Escape hatch `CTI_OPEN_ACCESS=true` (loud startup warning; docker-compose sets it deliberately). 702 tests. |
| **v0.9.0** | 2026-10-02 | **FTS5 full-text search** (v0.9.x track item 1): FTS5 tables per searchable type (articles/observables/entities/claims, `porter unicode61`), `bm25()` ranking + `snippet()` excerpts for `/search`, UI, MCP, AI retrieval; sanitized quoted-AND MATCH with LIKE fallback on Postgres/old SQLite/any OperationalError; idempotent batched startup backfill; incremental sync wired into ingest/OTX/full-fetch/pipeline writes. Design pivot caught by tests: external-content FTS5 corrupts on delete-after-content-change → regular (content-owning) tables instead. Entity alias search works now. Live-verified on the real 445-article DB. 730 tests. |
| **v0.10.0** | 2026-10-03 | **LLM idle-unload** (v0.9.x track item 2): embedded llama.cpp model (~2 GB RSS) released after `CTI_AI_IDLE_UNLOAD_S` idle seconds (default 900, 0=never); daemon reaper thread (starts on load, exits on unload); unload takes the inference lock + re-checks idleness under it → never mid-inference; next ask transparently reloads (~12s); lifespan shutdown unload; `/api/ai/status` gains `idle_seconds`/`idle_unload_s`. Live-verified: loaded → idle-flip at ~24s (TTL=20) → transparent reload, real answers both asks. 740 tests. |
| **v0.11.0** | 2026-10-03 | **Scheduled collection + email digest** (v0.9.x track item 3): scheduler digest job emails the daily report at HH:12 local (`CTI_DIGEST_EMAIL_ENABLED/TO/HOUR`, off by default; registered only when enabled+addressed; clean skip without SMTP; never raises; multipart plain+`text/markdown`; subject carries 24h article/high-risk counts). `scry scheduler install/uninstall/status/run` — launchd LaunchAgent writer (idempotent; venv python + repo cwd + absolute `CTI_DATABASE_URL`; `logs/` gitignored; loads only with `--load`); systemd example in `docs/scheduling.md`. Live-verified: SMTP-missing skip on real DB, plist correct in temp dir, real launchd untouched. 752 tests. |
| **v0.12.0** | 2026-10-03 | **Persisted semantic embeddings** (v0.9.x track item 4): article vectors computed once → new `article_embeddings` table (384-dim float32 packed, 1536 B/row; per-row `content_hash` rewrites only changed rows; stored `dim` auto-invalidates on algorithm change); write-time sync at the same hooks as FTS (ingest/OTX/full-fetch/pipeline-redaction); idempotent batched startup backfill (SQLite; Postgres keeps the legacy live path + write hooks); query path embeds only the query string, columnar vector load, numpy scoring with pure-Python fallback (numpy is not a base dep), self-healing stragglers; ranking unchanged (parity regression tests). Live-verified on the real 445-article DB: backfill 445/445, legacy↔persisted parity exact (REST top-5 ids [216, 154, 1, 323, 344] on both paths), 0.117s → 0.057s (~2×; per-query scaling O(N·text)→O(dim)). Isolation note: a full clean suite run provably never touches `./cti.sqlite` (canary experiment) — embeddings rows in the real DB came from an intentional mid-dev migration smoke-test against it (harmless: idempotent, hash-verified). 764 tests. |
| **v0.13.0** | 2026-10-03 | **Docker hardening** (v0.9.x track item 5): multi-stage Dockerfile — `builder` installs the pinned dep set into a venv, `python:3.12-slim` runtime copies only that venv (no toolchain/pip caches; zero runtime system packages — deps are self-contained wheels, `psycopg[binary]` bundles libpq); non-root `scry` user (uid 1000, `/app` the only writable tree); `HEALTHCHECK` probes `/health` via python urllib (curl dropped); new `requirements.lock` (104 exact pins; refresh recipe in `docs/installation.md`) replaces floating `pip install .`; unused `AS base` alias gone; base 3.11 → 3.12; `.dockerignore` += tests/docs/logs/coverage/`.github`/non-README Markdown. New `CTI_SECRET_FILE` setting relocates the auto-generated Fernet key (default path is read-only site-packages in installs) — Dockerfile sets `/app/data/.cti_secret`, compose mounts a new `cti_data` volume there on api+scheduler (previously container re-creation silently orphaned stored encrypted secrets). No Docker daemon on the release machine → verified by full container simulation (venv built **from the lock only** + `--no-deps .`, booted from a clean cwd: `/health` 200 in 6s, UI rendered from the wheel 22 KB, crypto roundtrip with key at `CTI_SECRET_FILE` mode 0600) + static compose/lock/`.dockerignore` assertions; `docker build` on a daemon host remains the final check. +3 crypto tests. 767 tests. |
| **v0.14.0** | 2026-10-03 | **raw_html retention pruning** (v0.9.x track item 6 — FINAL, track complete): new `scry/retention.py` — `prune_raw_html()` nulls ONLY `raw_html` for articles older than `raw_html_retention_days` (env `CTI_RAW_HTML_RETENTION_DAYS`, default 30, 0=keep forever; replaces the never-wired `retention_raw_html_days` placeholder); age = `COALESCE(ingested_at, published_at)`, ageless rows never pruned; row/`extracted_text`/FTS/embeddings/derived data kept (reprocess works off `extracted_text` → `extractor_version="0"` backlog unaffected); pruned articles are re-fetched on demand — `fetch_full_content` already selects `raw_html IS NULL` (regression-tested, no reader assumed a string: audit found only the parser DTO (None-safe) + ingest write paths). Weekly scheduler job Sun 04:47 UTC (clear of :04/:34/:19/:49 + digest HH:12; logs articles_pruned/bytes_reclaimed; never raises) + `scry prune-html [--days N] [--dry-run] [--no-vacuum]` (dry-run counts+bytes; real runs VACUUM SQLite). Live-verified (backup first → `cti-pre-prune-v0.14.0-2026-10-03.sqlite`, 8,134,656 B): dry-run@30d truthfully 0 candidates; `--days 1` pruned 80 articles / 613,642 B; VACUUM+checkpoint 7946K → 7268K; embeddings 445 / observables 746 / semantic top-5 unchanged; API readers return raw_html None + intact text; DB left pruned. +21 tests. 788 tests. |
| **v0.15.0** | 2026-10-03 | **FortiGuard Labs provider** — full IOC Research API v1.6 surface (`scry/enrichment/fortiguard.py`: search/related/visits/submissions/outbreaks + URL/IP/Domain/File batch+atomic endpoints incl. whois/ASN/geoip/AI summaries; enricher supports domain/url/ip/hash/email/onion-as-url; 7d TTL; Intel Feeds provider panel entry; `scry fortiguard` CLI ×17). **Scheduled enrichment pass** — `scripts/enrichment_runner.py` (resumable, time-boxed, DB-configured: non-VT pass + separate 4/min VT pass under the 480/day quota; progress + last-run stats in `system_settings`) + `scry/enrichment/schedule.py` + /admin → Scheduled enrichment card (toggle/providers/budgets, audit-logged). Onions now route to VT/OTX as URLs. Live-verified: FortiGuard key Connected; 36,239-observable local enrichment pass 18s; runner passes enriched 500 records non-VT + 25 VT per ~5-min run with 0 errors. |
| **v0.15.2** | 2026-10-03 | **Relationship evidence cap** — evidence was the whole surrounding "sentence"; punctuation-free imports copied 250 KB onto every relationship row (1.16 GB of a 1.3 GB DB). `evidence_window()` (400 chars, closest-pair endpoints, two fragments when far apart), pipeline sink guard, `scry prune-evidence`, idempotent startup trim. Live DB 1,348 MB → 126 MB. 812 tests. |
| **v0.16.0** | 2026-10-03 | **Scheduled full-page fetch + security hardening.** `fetch_full_content` wired into the scheduled ingest (bounded, age-windowed, failure back-off via `source_fetches`); single-URL ingest now parses pages; feeds sniffed by body; bcrypt >72-byte password crash fixed (pre-hash, 1,024-char cap); `Secure` auth cookies (`CTI_COOKIE_SECURE`); `/api/ai/provider` authenticated; `POST /sources` admin-only; tag-triggered release workflow. Live backfill of 341 stubs: +1,145 observables, +411 claims. 875 tests. |

**Session pattern that worked:** research/plan → implement step → run tests → live-verify on a running dev server → commit → repeat → release. Large features (auth, sources admin) were always split into 4–7 steps so progress survived session limits.

---

## 3. Architecture & Tech Stack

| Layer | Technology |
|---|---|
| Language | Python ≥ 3.11 (CI tests 3.11 + 3.12) |
| Web | FastAPI + uvicorn; server-rendered Jinja2 UI (27 templates, dark/light theme, no JS framework) |
| Database | SQLite by default (`cti.sqlite`); SQLAlchemy 2.0 ORM (18 models); Alembic migrations + startup auto-migration; optional Postgres + pgvector via Docker |
| CLI | Typer (`scry` entry point) — init-db, ingest-*, extract, enrich, search, semantic-search, ai-setup, stats, mcp, users, feeds, sources, reviews, alerts, reporting, lifecycle |
| Scheduling | APScheduler (in-process; optional separate compose service) |
| AI | Provider abstraction in `scry/ai/providers/` (local GGUF via llama-cpp-python, Ollama, OpenAI, Anthropic, Google, xAI); persisted offline hash-embedding semantic search (pgvector planned) |
| Auth | bcrypt, DB-backed sessions (sliding 7-day), TOTP (pyotp + qrcode), WebAuthn (webauthn ≥2.0), per-user API keys |
| Crypto | Fernet (cryptography ≥42) for at-rest secrets; key file `.cti_secret` (gitignored; relocatable via `CTI_SECRET_FILE`) |
| Quality | pytest (788 tests), ruff, black, mypy; CI matrix on push/PR; gitleaks secret scanning |
| Integrations | Feedparser/trafilatura/readability/bs4 (parsing), httpx + tenacity (fetch), structlog, orjson |

### Key subpackages (`scry/`)

- `ingestion/` — fetcher (retry/backoff, browser-like headers), RSS, CVE feed, OTX pulses, SSRF guard, policy engine, source registry, collection window
- `extraction/` — IOC/entity/claim/relationship extractors, defang, classifiers, LLM hook (stubbed by design)
- `enrichment/` — providers (virustotal, otx, greynoise, abuseipdb, fortiguard), engine, rate limiting, per-user keys, schedule settings (`enrichment.schedule.*` in `system_settings`)
- `ai/` — provider registry + per-provider implementations + prompts
- `auth/` — passwords, sessions, TOTP, WebAuthn, verification
- `api/` — REST routers incl. TAXII 2.1 and API-key dependency
- `alerting/`, `scoring/`, `exports/` (incl. spec-valid STIX 2.1), `search/`, `parsing/` (incl. redactor), `reporting/`, `review/`, `models/`, `schemas/`, `ui/`
- Top level: `main.py` (app factory + all `/ui/*` routes), `cli.py`, `config.py`, `db.py`, `scheduler.py`, `mcp_server.py`, `crypto.py`, `audit.py`, `http.py`, `deduplication.py`, `clustering.py`, `conflicts.py`

---

## 4. File & Folder Structure — Local vs GitHub

### 4.1 What lives on GitHub (tracked, 273 files)

```
cti-enrichment-agent/
├── scry/                  # the application package (~130 modules, 2.6 MB)
│   ├── ai/  api/  auth/  alerting/  connectors/  enrichment/  exports/
│   ├── extraction/  ingestion/  models/  parsing/  reporting/
│   ├── review/  scoring/  schemas/  search/  ui/  (templates + static)
│   └── main.py cli.py config.py db.py scheduler.py mcp_server.py ... (top-level modules)
├── tests/                 # 49 test files + conftest + 8 .txt fixtures (2.2 MB)
├── config/                # sources.yaml (37 sources), policies.yaml, aliases.yaml,
│                          # otx_pulses.yaml, watchlists.yaml, pirs.yaml
├── scripts/               # 5 standalone utility scripts
├── docs/                  # installation / configuration / usage-cli / ui-guide /
│                          # api-reference / development (+ archive/)
├── alembic/               # migration env + 0001_initial
├── .github/workflows/     # ci.yml (ruff/black/pytest matrix) + secret-scan.yml (gitleaks)
├── .githooks/pre-commit   # local secret-scan hook (enabled via core.hooksPath)
├── pyproject.toml Makefile Dockerfile docker-compose.yml alembic.ini package.json
├── .env.example .gitignore .gitleaks.toml
├── README.md CHANGELOG.md FEATURES.md SECURITY.md ARCHITECTURE.md DATA_MODEL.md
├── SCORING.md SOURCES.md CONNECTORS.md INTEGRATIONS.md CONTRIBUTING.md LICENSE
```

### 4.2 What exists only locally (gitignored — never on GitHub)

| Path | What it is | Why it's local |
|---|---|---|
| `.env` | Real environment config: live API keys, DB URL, master `CTI_API_KEY` | Secrets — `.env.example` is the documented template |
| `.cti_secret` | Fernet encryption key for at-rest secrets | Secret material; regenerated per install |
| `cti.sqlite` | The actual intelligence database | **Data**, not code — each install builds its own |
| `data/` (~1 GB) | Raw HTML, caches, downloaded LLM models | Data + large binaries |
| `analytics_exports/`, `reports/` | Generated reports/exports | Generated artifacts |
| `.venv/`, `__pycache__/`, `*.egg-info/`, `.mypy_cache/` etc. | Python environment/build caches | Machine-specific |
| `*.log`, `*.out` | Runtime logs | Operational noise |

**Consequence for multi-machine use:** cloning the repo gives you the *entire application*; each machine gets its own `.env` (from `.env.example`), own Fernet key, own database, own users (first-run `/setup` page), and own threat-feed API keys. Code updates flow through git; data does not.

### 4.3 Satellite systems (outside the repo)

Personal Kimi Work Blueprint widgets on a local Dashboard (threat stats, intel-feed status, latest OTX pulses with a 15-minute auto-refresh toggle) read the scry database/API locally. They are **personal automations, not part of the project** — ignore them when working on the repo, and never move their scripts/config into git.

---

## 5. Run, Verify, Test

```bash
# Zero-infra install (SQLite)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # + ".[ai]" for the local LLM, ".[mcp]" for MCP
scry init-db                       # schema + sync sources.yaml → DB
uvicorn scry.main:app --reload     # http://localhost:8000  (/docs = OpenAPI)
# First visit with zero users → /setup creates the first admin

# Everyday verification loop
.venv/bin/pytest -q                # 788 tests must pass
.venv/bin/ruff check scry tests
scry ingest-source "CISA Advisories" && scry stats

# Docker path (Postgres + pgvector): cp .env.example .env && docker compose up -d postgres
#   && docker compose run --rm api alembic upgrade head && docker compose up api
```

Server config: host/port via `CTI_API_HOST`/`CTI_API_PORT` (default 8000; a local dev instance may run on 7100 via launcher glue). zsh caveat: `#` in pasted commands isn't a comment — don't paste trailing comments.

---

## 6. GitHub-as-Backup Policy & Secrets Hygiene

- **GitHub is the off-site backup for code and docs.** Push after every step; release at the end of every track. Verify parity occasionally (fresh-clone diff against the working tree).
- **Never commit:** live API keys, passwords, the Fernet key, databases, raw HTML, logs, personal names/emails/paths. Placeholders only (`your_key_here`, `example.com`).
- **Enforced by tooling** (added v0.7.1): pre-commit hook blocks credential-shaped strings in staged diffs (bypass `SKIP_SECRET_SCAN=1` for intentional fixtures); CI runs gitleaks on every push/PR with full history.
- **History caveat:** the pre-v0.7.1 default seed password exists in old tags' history (accepted; the string is allowlisted in `.gitleaks.toml` so scans stay green). Never rewrite published history; rotate exposed credentials instead.
- **Commit identity** uses GitHub's noreply address; no personal email in commit metadata.

---

## 7. Current State & Active Roadmap

**Current:** v0.16.0 released — scheduled full-page fetch for feed stubs (`CTI_FULL_FETCH_*`), Secure auth cookies (`CTI_COOKIE_SECURE`), authenticated `/api/ai/provider`, admin-only `POST /sources`, >72-byte password fix, single-URL ingest parsing, tag-triggered release workflow; 875 tests green. Prior: v0.15.2 released — relationship evidence capped at 400 chars (`scry/extraction/relationship_extractor.py` `evidence_window`, sink guard in pipeline, `scry prune-evidence`, startup trim); live DB 1.3 GB → 126 MB; 812 tests green. Prior: v0.15.1 released — FortiGuard joins the Threat Feeds "My API keys" card (personal keys + live lookup + verdict panel) and bulk-import origins (`local://` sources) are hidden from the Sources page while their data stays in the DB. Prior: v0.15.0 FortiGuard Labs provider + scheduled external-enrichment pass. 793 tests green (~60s suite). CI + secret scanning green. Open follow-ups: passive-DNS real-data verification — crt.sh was returning 502; the next `POST /enrichment/run?providers=passive_dns` backfills automatically once the service recovers. Docker: no daemon on the release machine — image verified by container simulation + static checks; run `docker build` once on a daemon-equipped host as the final check.

**TRACK COMPLETE — v0.9.x "scale & ops" (owner-approved 2026-10-02; all six items shipped as minor releases 2026-10-02 → 2026-10-03):**

| # | Feature | Status |
|---|---|---|
| 1 | **FTS5 full-text search** (replace leading-wildcard LIKE scans across articles/observables/entities/claims; ~~external-content FTS5 tables + triggers~~ → regular content-owning FTS5 tables + write-path sync on SQLite (external content corrupts on delete-after-update), keeps Postgres path working; AI retrieval benefits automatically) | ✅ shipped as **v0.9.0** |
| 2 | **LLM idle-unload** (release the ~2 GB local-model RSS after ~15 min idle; `CTI_AI_IDLE_UNLOAD_S`; reload on next ask) | ✅ shipped as **v0.10.0** |
| 3 | **Scheduled collection + email digest** (ensure scheduler runs daily — launchd/systemd docs or in-app; daily report delivered via existing mail.py SMTP) | ✅ shipped as **v0.11.0** |
| 4 | **Persisted semantic embeddings** (embed at ingest, store vectors, query-time cosine instead of re-embedding the corpus per search) | ✅ shipped as **v0.12.0** |
| 5 | **Docker hardening** (multi-stage build, non-root user, healthcheck, slim image) | ✅ shipped as **v0.13.0** |
| 6 | **`raw_html` retention pruning** (configurable retention; raw HTML only needed for re-extraction; lifecycle job) | ✅ shipped as **v0.14.0** |

Known issues accepted in v0.8.1 (from deep review, do not re-report): DNS-rebinding IP pinning documented-only (TLS SNI trade-off); FTS5/embeddings were the accepted deferral now scheduled as items 1+4 above.

**Deferred / longer roadmap (from README/FEATURES):**
- pgvector + real embedding model to replace hash-embedding semantic search
- Passive enrichers (passive DNS, WHOIS, cert transparency, EPSS) — interface exists
- Sigma/YARA/Suricata generation with false-positive guardrails (human validation required)
- Internal sightings connector (DNS/proxy/EDR) — schema in place
- MISP/OpenCTI/SIEM connectors currently dry-run stubs
- LLM extraction stubbed by design — deterministic extractors carry the load; no LLM claim stored without evidence
- Future: `scry backup`/`scry restore` command pair for moving code *and* data between machines

**Locked conventions to respect:**
- Scheduled jobs use the system key; user-triggered actions use the acting user's key.
- Intel data is shared across users; per-user privacy applies to chat sessions and action attribution only.
- Collection is global; source toggles and the collection window are admin-only.
- Threat-feed connectors don't re-enrich already-enriched data by default (staleness TTLs + `force` override).

---

## 8. THE MASTER PROMPT (give this to any AI coding assistant)

Copy everything in the fenced block below verbatim. It contains everything a model needs to work on or recreate the project.

````text
# MISSION
You are working on "scry" — a self-hosted threat-intelligence platform (defensive
security OSINT collector/extractor/enricher with web UI, REST API, MCP server,
STIX 2.1/TAXII 2.1 export, and multi-user auth). Public repo:
https://github.com/altered-intelligence/scry (Apache-2.0). Current version: 0.16.0.

If the repo is not present, clone it and set up:
    python3 -m venv .venv && source .venv/bin/activate
    pip install -e ".[dev]"          # + ".[ai]" for the local LLM, ".[mcp]" for MCP
    cp .env.example .env             # fill in keys ONLY locally; never commit them
    scry init-db
    uvicorn scry.main:app --reload   # http://localhost:8000
First visit with zero users opens /setup to create the first admin.

# STACK (verify against pyproject.toml before assuming)
Python ≥3.11 · FastAPI + uvicorn · SQLAlchemy 2.0 (SQLite default, Postgres+pgvector
optional) · Alembic · Jinja2 server-rendered UI · Typer CLI (`scry`) · APScheduler ·
provider-based AI (local GGUF llama-cpp-python / Ollama / OpenAI / Anthropic / Google /
xAI) · bcrypt + TOTP + WebAuthn auth · Fernet at-rest secret encryption (key file
.cti_secret) · pytest (788 tests) · ruff/black/mypy · gitleaks CI.

# GOLDEN RULES (non-negotiable)
1. DEFENSIVE-ONLY: never weaken SECURITY.md boundaries — SSRF guard, fail-closed
   collection policies, secret redaction, no malware download, no credential/PII
   collection, no offensive automation, dark-web disabled by default.
2. NO SECRETS IN THE REPO: placeholders only (.env.example documents every CTI_*
   variable). The pre-commit hook blocks credential-shaped strings; bypass only for
   intentional test fixtures via SKIP_SECRET_SCAN=1. Never commit .env, .cti_secret,
   *.sqlite, data/, logs, or personal information.
3. FEATURE TRACKS: implement each change as small, independently-committed steps
   (prefix "vX.Y.Z step N:"). FULL test suite must pass before every commit
   (.venv/bin/pytest -q). Verify existing scaffolding before adding new code.
4. LIVE-VERIFY before releasing: run the server and exercise the feature end-to-end.
5. RELEASE = bump version (scry/main.py + pyproject.toml), CHANGELOG.md entry
   (Keep a Changelog), README "What's new" section, commit "Release vX.Y.Z: ...",
   tag, push, `gh release create`. Verify tag == HEAD == remote HEAD.
6. Auth conventions: scheduled jobs use the system key; user actions use the acting
   user's key. REST API routes + /taxii2 require auth once any user exists (main
   API at root paths like /observables; only /api/ai/*, /api/reports/brief, and
   /taxii2/* carry a prefix). Intel data is
   shared across users; per-user privacy only for chat + action attribution.
7. Never rewrite published git history. Rotate exposed credentials instead.
8. Don't touch satellite systems (personal dashboards/automations outside the repo).

# PROJECT CONVENTIONS
- Feature tracks are planned in FEATURES.md (all historical tracks complete — read
  them as examples of the step style). CHANGELOG.md is authoritative for history.
- README.md, ARCHITECTURE.md, DATA_MODEL.md, SCORING.md, SECURITY.md, SOURCES.md,
  CONNECTORS.md, INTEGRATIONS.md, docs/ are maintained — update docs you touch.
- config/*.yaml drives sources, policies, aliases, OTX subscriptions, watchlists,
  PIRs without code changes.
- Deferred roadmap: pgvector semantic search, passive enrichers, Sigma/YARA
  generation with FP guardrails, sightings connector, real MISP/OpenCTI/SIEM
  connectors, scry backup/restore commands.

# DEFINITION OF DONE for any task
Tests green · ruff clean · feature live-verified on a running server · docs updated ·
CHANGELOG updated (if user-facing) · committed in step-sized commits · pushed.

# FIRST ACTION when picking up mid-project
Run: git status && git log --oneline -10 && git tag --sort=-v:refname | head -3
Read CHANGELOG.md top section + FEATURES.md bottom (current/most recent track).
Report current state before making changes.
````

---

*Generated 2026-10-01. Keep this file beside the repo (or in the repo root as
`HANDOFF.md`) and refresh the version numbers whenever you release.*
