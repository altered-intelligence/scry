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
- [ ] **Step 5 — Ask follow-up memory.** Wire `ChatSession`/`ChatMessage`:
  `POST /api/ai/ask` accepts optional `session_id`; history (last N turns) is
  prepended to the model context; assistant reply + sources persisted.
  `GET /api/ai/sessions`, `GET /api/ai/sessions/{id}`, `DELETE /api/ai/sessions/{id}`,
  `POST /api/ai/sessions` (rename). Search-page AI panel gains conversation
  list + history display. No schema migration needed (models use
  `Base.metadata.create_all`).
- [ ] **Step 6 — External IOC enrichment providers.** Audit `scry/enrichment/`;
  finish/wire VirusTotal + OTX (keys already in Settings), add AbuseIPDB
  (IP) and GreyNoise (IP) as providers following the existing
  `enrichment/base.py` interface. `POST /api/enrichment/run` gains
  `providers` filter. Per-provider enable toggles + key fields on a settings
  surface (reuse provider-picker pattern from Search page). Rate-limit
  bookkeeping respects `vt_rate_per_min`, `vt_daily_quota`, `otx_rate_per_sec`.
  Tests with mocked HTTP.
- [ ] **Step 7 — STIX 2.1 export + TAXII feed.** New `scry/exports/stix21.py`
  emitting spec-valid STIX 2.1 bundles (SDOs for threat-actors, malware,
  campaigns, indicators, relationships; SCOs for observables; marking
  `spec_version: "2.1"`). `POST /api/exports/stix21`. Minimal read-only TAXII
  2.1 server: `GET /taxii2/` (server discovery), `GET /taxii2/{api-root}/`
  (api-root discovery), `GET .../collections/`, `GET .../collections/{id}/objects/`
  (paged STIX objects), auth via same `require_api_key` when configured.
  Tests validating bundle structure + TAXII discovery JSON.

## Release (after all steps)
- [ ] Bump version to 0.4.0 (app version in `scry/main.py`, `pyproject.toml`,
      `CHANGELOG.md`, README feature list), tag `v0.4.0`, push + GitHub release
      via `/opt/homebrew/bin/gh`.
