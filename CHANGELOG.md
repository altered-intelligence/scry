# Changelog

All notable changes to Scry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
semantic versioning.

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
