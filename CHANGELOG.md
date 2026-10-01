# Changelog

All notable changes to Scry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
semantic versioning.

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
