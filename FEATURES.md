# scry v0.4.0 feature track

Seven features, each implemented as one independently-committed step so work can
pause/resume across sessions without loss. **To resume:** find the first
unchecked step below, implement it, run `pytest`, commit, check the box.

Conventions for every step:
- Commit message prefix: `v0.4.0 step N:` (e.g. `v0.4.0 step 1: API token auth`).
- Run the full test suite (`python -m pytest tests/ -q`) before committing.
- Do NOT touch the Blueprint/Dashboard assets under `~/Library/Application Support/kimi-desktop/...` — those are runtime glue, not repo content.
- Existing scaffolding to build on (verify state before writing new code):
  - `scry/alerting/channels.py` — Slack/Teams webhook stubs, wired into `AlertEngine.evaluate()` but only when `CTI_ENABLE_OUTBOUND_ALERTS=true`.
  - `scry/models/chat.py` — `ChatSession`/`ChatMessage` models exist but NOTHING uses them yet (no endpoints, no UI).
  - `scry/enrichment/` — virustotal.py, otx.py, url.py, infrastructure.py, vulnerability.py, engine.py, base.py (check what is real vs stub).
  - `scry/exports/stix_like.py` — STIX-like export exists; not spec-valid STIX 2.1.
  - `scry/reporting/daily.py`, `weekly.py` — plain-text reports; `/api/reports/daily|weekly`.
  - `scry/ai/` — provider registry (`resolve_ai_provider`), providers in `scry/ai/providers/`, prompts in `scry/ai/prompts.py`.
  - `scry/api/router.py` + `scry/api/ai.py` — all REST under `/api/*`; `scry/main.py` mounts both routers plus `/ui/*` HTML routes.
  - Config: `scry/config.py` `Settings` (env prefix `CTI_`, `.env` file).
  - No auth anywhere — all endpoints are open.

## Steps

- [x] **Step 1 — API token auth.** Optional static API key: new `Settings.api_key`
  (env `CTI_API_KEY`). When set, all `/api/*` routes require it via
  `X-API-Key` header or `Authorization: Bearer <key>`; `/api/health` and all
  `/ui/*` routes stay open. Implement as a FastAPI dependency in a new
  `scry/api/auth.py`, wired with `dependencies=[Depends(require_api_key)]` on
  `include_router` calls in `scry/main.py`. When `api_key` is empty: no auth
  (current behavior). Constant-time compare. Tests + README/SECURITY.md note.
- [x] **Step 2 — MCP server wrapper.** New `scry/mcp_server.py` exposing scry
  tools over stdio (official `mcp` package, add to pyproject): `scry_search`,
  `scry_ask`, `scry_observables`, `scry_alerts`, `scry_stats`, `scry_health`.
  Thin adapters over existing service functions (import, don't reimplement).
  CLI entry `scry mcp` in `scry/cli.py`. README section with client config
  snippets (Claude Desktop / Cursor). Tests for tool handlers.
- [x] **Step 3 — AI-synthesized briefs.** `POST /api/reports/brief?scope=daily|weekly`
  pipes the existing plain-text report through the active `resolve_ai_provider`
  LLM into an executive summary; result cached in-memory per scope/day.
  UI button on reports area + `scry reporting brief --scope daily` CLI. Reuse
  provider/registry code from `scry/api/ai.py` (factor shared helper if clean).
  Tests with stub provider.
- [x] **Step 4 — Alert notifications.** Extend `scry/alerting/channels.py`:
  generic webhook (`CTI_WEBHOOK_URL`), email via SMTP
  (`CTI_ALERT_EMAIL_*` + `CTI_SMTP_HOST/PORT/USER/PASSWORD`), macOS desktop
  notification (`osascript`, no extra deps). Add `POST /api/alerts/test` that
  sends a test message through every configured channel. Settings panel section
  on `/ui/alerts` showing channel state + test button. Auto-run
  `AlertEngine.evaluate()` at end of `/api/ingest/run` (behind existing
  `CTI_ENABLE_OUTBOUND_ALERTS` gate for delivery only — alerts always recorded).
- [x] **Step 5 — Ask follow-up memory.** Wire `ChatSession`/`ChatMessage`:
  `POST /api/ai/ask` accepts optional `session_id`; history (last N turns) is
  prepended to the model context; assistant reply + sources persisted.
  `GET /api/ai/sessions`, `GET /api/ai/sessions/{id}`, `DELETE /api/ai/sessions/{id}`,
  `POST /api/ai/sessions` (rename). Search-page AI panel gains conversation
  list + history display. No schema migration needed (models use
  `Base.metadata.create_all`).
- [x] **Step 6 — External IOC enrichment providers.** Audit `scry/enrichment/`;
  finish/wire VirusTotal + OTX (keys already in Settings), add AbuseIPDB
  (IP) and GreyNoise (IP) as providers following the existing
  `enrichment/base.py` interface. `POST /api/enrichment/run` gains
  `providers` filter. Per-provider enable toggles + key fields on a settings
  surface (reuse provider-picker pattern from Search page). Rate-limit
  bookkeeping respects `vt_rate_per_min`, `vt_daily_quota`, `otx_rate_per_sec`.
  Tests with mocked HTTP.
- [x] **Step 7 — STIX 2.1 export + TAXII feed.** New `scry/exports/stix21.py`
  emitting spec-valid STIX 2.1 bundles (SDOs for threat-actors, malware,
  campaigns, indicators, relationships; SCOs for observables; marking
  `spec_version: "2.1"`). `POST /api/exports/stix21`. Minimal read-only TAXII
  2.1 server: `GET /taxii2/` (server discovery), `GET /taxii2/{api-root}/`
  (api-root discovery), `GET .../collections/`, `GET .../collections/{id}/objects/`
  (paged STIX objects), auth via same `require_api_key` when configured.
  Tests validating bundle structure + TAXII discovery JSON.

## Release (after all steps)
- [x] Bump version to 0.4.0 (app version in `scry/main.py`, `pyproject.toml`,
      `CHANGELOG.md`, README feature list), tag `v0.4.0`, push + GitHub release
      via `/opt/homebrew/bin/gh`.

---

# scry v0.5.0 feature track — user accounts, auth, admin

Same conventions as v0.4.0: one committed step at a time, full test suite
(`.venv/bin/pytest -q`, currently 242 passed) green before each commit, commit
prefix `v0.5.0 step N:`. Owner decisions locked 2026-09-29:

- Background/scheduled ingest+enrichment uses the SYSTEM key (env/DB chain);
  user-triggered actions (test button, verdict panel, manual enrich) use the
  ACTING USER's personal VT/OTX keys; no personal key → provider skipped; all
  enriched data stays shared in the common DB.
- Per-user privacy: AI chat sessions visible only to their owner; reviews/alert
  acks attributed to acting user. Intel data itself stays shared.
- WebAuthn relying-party derived per-request from Host — works on localhost
  now and LAN+HTTPS later.
- Email required for all users. SMTP not configured → email verification
  bypassed (auto-verified). SMTP configured → 6-digit PIN emailed, required at
  first login; same code path serves future password reset. Admin SMTP config
  page with test button; all SMTP functions bypass cleanly when unset.
- Once ANY user exists: /api/* requires auth (session cookie, per-user API
  key, or master CTI_API_KEY). Master key generated into .env + added to
  Dashboard widget scripts. No users → legacy open behavior.
- Seeded admins: alakhani + admin, password "Batman911!#", must change at
  first login, MFA/passkeys off initially. Existing VT/OTX keys migrated from
  .env into both profiles.

## Steps

- [x] **Step 1 — Accounts core.** User + SessionToken models (scry/models/user.py);
  bcrypt password hashes; DB-backed sessions (HttpOnly cookie, sliding 7-day
  expiry, "log out everywhere"); /login /logout pages; middleware gating /ui/*
  + future /admin behind session (redirect to /login; /login + /static exempt);
  login throttling (5 fails → 15-min lockout); email column required;
  `scry users` CLI (create/list/promote/demote/reset-password/disable/seed);
  seed alakhani+admin (must_change_password=true); extension of
  scry/api/auth.py: when users exist require session cookie OR valid API key
  OR master CTI_API_KEY (per-user keys land in step 3 — design the dependency
  so keys are pluggable); exemptions /health /api/health /api/ai/status
  /api/ai/provider GET stay as today.
- [x] **Step 2 — Roles + /admin.** Role column (user|admin); /admin gated to
  admins (403 page otherwise); admin dashboard: user table (create/edit role/
  disable/reset password/delete), app stats reuse, failed-logins/lockouts
  panel, admin audit via scry/audit.py. Nav link visible to admins only.
  Plus SMTP config (locked decision 4b): DB-stored admin SMTP server
  (scry/models/system.py + scry/mail.py) overriding env fallback, password
  encrypted, /admin test button, clean bypass when unconfigured.
- [x] **Step 3 — /profile + per-user scry API keys + email verification.**
  /profile page: display name, change password (enforces must_change_password),
  email verification status + PIN entry UI; per-user API keys (create/revoke,
  masked after creation, last-used tracking); SMTP mailer module (scry/mail.py)
  using alert SMTP settings + DB-stored admin SMTP config with test — dormant
  when unconfigured; verification PIN generated/stored, emailed when SMTP up,
  bypassed otherwise.
- [x] **Step 4 — TOTP MFA.** pyotp; setup flow (secret + otpauth URI + QR via
  qrcode lib), verify-before-enable, disable (password confirm), required at
  login when enabled; 10 one-time recovery codes shown once at setup;
  recovery-code login path. Admin can force-disable MFA.
- [x] **Step 5 — Passkeys.** webauthn package; register/rename/delete on
  /profile; login via passkey (WebAuthn get assertion); per-request RP
  ID/origin from Host; works localhost + LAN/HTTPS.
- [x] **Step 6 — Per-user threat-feed keys + feed features.** VT/OTX cards on
  /ui/intel-feeds/threat-feeds: per-user key input (visible while typing,
  masked after save+test), Test → Connected/Failed badge; migrate existing
  .env keys into alakhani+admin profiles (encrypted); enrichment run uses
  acting user's keys; observable detail verdict panel (live lookup, personal
  key); bulk "enrich unenriched" with quota guard; enriched badges in
  observable lists; enrichment coverage stats (admin).
- [x] **Step 7 — Master key + widget wiring.** Generate strong random
  CTI_API_KEY into .env; add X-API-Key header to the three Dashboard widget
  automation scripts under the kimi-desktop blueprint dir (ask scry, AI
  provider, server status); verify each widget still works end-to-end.
- [x] **Step 8 — Release.** Bump 0.4.0 → 0.5.0 (pyproject, main.py app
  version, CHANGELOG, README), tag v0.5.0, push, GitHub release via
  /opt/homebrew/bin/gh.

---

# scry v0.6.0 feature track — OTX pulses, alert escalation, enrichment refresh

Conventions as before: committed steps, `.venv/bin/pytest -q` green (459 passed
baseline), prefix `v0.5.0`→`v0.6.0 step N:`. Owner-approved 2026-09-30.

Context: the enrichment batch ALREADY skips observables carrying a
`{provider}_checked_at` marker (default no-repeat). This track makes that
guarantee explicit, adds staleness-based refresh, vendor-verdict alert
escalation, and OTX pulse ingestion as a first-class source.

- [x] **Step 1 — OTX pulse ingestion.** `config/otx_pulses.yaml` subscriptions
  (name, query, tags, max_pulse_age_days default 30, limit default 25).
  `scry/ingestion/otx_pulses.py`: pull matching pulses via OTX API
  (/api/v1/search/pulses?q=...), store each pulse as an Article (source
  `otx_pulse:<name>`, url = pulse page URL, summary = description, tags merged,
  published date) so the existing extraction/enrichment pipeline picks up IOCs;
  dedup via existing article URL dedup; no-op on unchanged content. Key
  resolution: background/scheduled → system OTX key; user-triggered pull →
  acting user's personal OTX key (locked v0.5 rule). `POST /ingest/otx-pulses`
  (optional subscription filter), `scry ingest otx-pulses` CLI, subscriptions
  summary + pull-now on the threat-feeds UI page, scheduler hook alongside
  existing ingest jobs. Disabled entirely when no OTX key anywhere.
- [x] **Step 2 — Vendor-verdict alert escalation.** AlertEngine gains
  `_vendor_confirmed_alerts()`: observables whose enrichment JSON shows VT
  malicious votes >= `vt_escalate_min_detections` (default 10) AND ratio >=
  `vt_escalate_min_ratio` (default 0.5), OR GreyNoise classification ==
  "malicious", OR AbuseIPDB score >= `abuseipdb_escalate_min_score` (default
  80) → AlertCandidate trigger `vendor_confirmed_malicious` (dedup key per
  observable+provider), plus an observable risk_score bump (cap 100) on
  confirmation. Thresholds as Settings (env-tunable CTI_*). Alerts page badge
  for the new trigger.
- [x] **Step 3 — Enrichment idempotency + refresh.** Per-provider staleness TTL
  (Settings `enrichment_refresh_days_<provider>`, defaults: virustotal 7,
  otx 14, abuseipdb 7, greynoise 3): batch re-enriches ONLY observables whose
  `{provider}_checked_at` is missing OR older than TTL (fresh ones counted as
  `fresh_skipped`); `force=true` on POST /enrichment/run ignores markers.
  Bulk runs order oldest-checked-first (quota goes to stalest data). UI:
  observable detail shows per-provider "last enriched Xd ago" + per-provider
  Re-check (existing live lookup, labeled); observables page gains
  "Re-enrich stale" and "Force re-enrich all" (confirm-guarded); admin
  coverage table adds fresh/stale counts.
- [ ] **Step 4 — Deploy + live verify.** Touch-restart the uvicorn --reload
  server, verify: OTX pulse pull with real key (small limit), escalation rule
  dry presence, enrichment run reports fresh_skipped on second pass.
- [ ] **Step 5 — Release.** 0.5.0 → 0.6.0 bump, CHANGELOG, README, tag,
  push, GitHub release via /opt/homebrew/bin/gh.
