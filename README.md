<p align="center">
  <img src="docs/assets/social-preview.png" alt="Scry — Seeing threats before they arrive" width="640">
</p>

# <img src="scry/ui/static/logo.svg" alt="" width="30" valign="middle"> Scry

[![CI](https://github.com/altered-intelligence/scry/actions/workflows/ci.yml/badge.svg)](https://github.com/altered-intelligence/scry/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

*Seeing threats before they arrive.*

A defensive cyber threat intelligence platform that ingests public sources, extracts IOCs / entities / claims / relationships, enriches and scores them, surfaces high-risk items for analyst review, and produces daily / weekly reports — preserving source provenance, confidence, and context the whole way through.

> **Why "Scry"?** Scrying is the old art of divination — gazing into a crystal ball to see what is coming before it arrives. That is exactly the job of this platform: watch the public threat landscape, extract the signal, and surface what's about to matter to defenders. (Formerly "CTI Enrichment Agent"; the env var prefix `CTI_`, database file `cti.sqlite`, and this project directory name are kept for backwards compatibility.)

> **Defensive use only.** This system is built strictly for defenders. See [`SECURITY.md`](./SECURITY.md) for the safety boundaries enforced in code (SSRF guard, collection policy engine, secret redaction, no malware download, no credential collection, dark-web disabled by default, no offensive automation).

---

## What it does

- **Ingests** public RSS / blogs / vendor research / CISA KEV / Reddit (and any source you add to `config/sources.yaml`) under per-source collection policies.
- **Parses** articles (trafilatura → readability → bs4 fallback), normalizes Unicode, redacts credentials / API keys / private keys before indexing.
- **Extracts** IPv4/IPv6, domains, URLs, defanged variants, emails, hashes (MD5/SHA1/SHA256/SHA512/SSDEEP/TLSH), CVEs, ATT&CK techniques, ASNs, onion, wallets, registry keys, named pipes, Telegram/Discord handles — with evidence text and confidence scores.
- **Identifies** threat actors and malware families via a curated alias dictionary, then resolves aliases to canonical names.
- **Builds claims** as first-class objects ("exploited in the wild", "attributed to APT29", "ransomware deployed", "AppDomainManager hijacking", "AI-enabled phishing", "targets US defense industrial base", …) — every claim carries an evidence quote.
- **Builds relationships** between observables / entities / CVEs with explicit_or_inferred provenance.
- **Classifies topics** for every article: `microsoft`, `ransomware`, `wiper`, `exploit-poc`, `exploited-in-the-wild`, `appdomainmanager-hijacking`, `ai-security`, `defense-industry`, `supply-chain`, `infostealer`, `phishing`, `cloud`, `ics-ot`, `apt`.
- **Enriches** observables with structural infrastructure attributes (cloud / CDN / dynamic-DNS / paste-site / URL-shortener / benign-shared-infrastructure flags), URL roles, email lure hints, CVE/KEV details, ATT&CK technique names + tactics, and prevalence/rarity.
- **Scores** each item with a transparent multi-factor model: source reliability, extraction confidence, maliciousness, attribution, corroboration, recency. Risk score has contributor breakdown so analysts can see *why* a score is what it is.
- **IOC lifecycle / decay**: type-specific TTLs (cloud hosts decay faster than dedicated infra; CVEs never expire; expired indicators stay searchable but aren't block-recommended).
- **Routes to analyst review** when confidence is low, attribution is weak/disputed, claims touch nation-state activity or ransomware victim naming, or high-risk + benign-shared-infrastructure context collides.
- **Detects conflicts** between articles (e.g. two vendors attribute the same activity to different actors). Both claims are preserved.
- **Clusters** related articles by shared IOCs / entities (union-find).
- **Alerts** on CISA KEV additions, Microsoft exploited CVEs, high-risk observables, ransomware reporting. Outbound delivery (Slack / Teams / webhook) is **off by default** and only fires when `CTI_ENABLE_OUTBOUND_ALERTS=true`.
- **Search**: full-text across articles / observables / entities / claims, plus a hash-embedding semantic search that works offline (a pgvector adapter slots in behind the same interface later).
- **Reports**: daily and weekly Markdown summaries with confidence legend, top stories, KEV updates, high-risk observables, review queue digest, and collection gaps.
- **Exports**: JSON, CSV, STIX-like bundle, spec-valid **STIX 2.1** bundles, and a read-only **TAXII 2.1** server (MISP / OpenCTI / Sentinel can poll scry directly).

## What it deliberately does *not* do

The collection policy engine fails closed for anything risky. The system does **not**:

- Authenticate to criminal services or join private forums
- Collect stolen credentials, victim data dumps, or leaked PII
- Buy / validate / interact with illicit data
- Download or execute malware / exploit code / unknown binaries
- Bypass paywalls / CAPTCHAs / robots.txt / authentication / rate limits
- Auto-clone exploit repositories
- Submit forms to suspicious sites
- Render JavaScript by default
- Connect to onion / dark web sources by default (passive metadata only, *explicitly* opt-in)
- Initiate any outbound alert / webhook unless explicitly configured

LLM extraction is stubbed by default and the deterministic extractors do the heavy lifting. The LLM interface is pluggable, but **no LLM-generated claim is ever stored without evidence text from the source**.

## Quick start

### Zero-infra (SQLite)

> **Heads-up for zsh users:** zsh's interactive mode does *not* strip `#` comments by default — pasting a line like `scry init-db  # comment` will pass the comment as an argument and the command will error. Either run `setopt interactive_comments` once, or paste the commands without trailing comments.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Optional: pin SQLite as the DB (this is also the default)
export CTI_DATABASE_URL="sqlite+pysqlite:///./cti.sqlite"

scry init-db
scry sources list
scry ingest-source "SANS ISC"
scry stats
scry report daily

# Launch the UI — the app self-initializes the schema on startup
uvicorn scry.main:app --reload
```

Then open <http://localhost:8000/>.

### Production-ish (Docker, Postgres + pgvector)

```bash
cp .env.example .env
docker compose up -d postgres
docker compose run --rm api alembic upgrade head
docker compose run --rm api python -c "from scry.db import session_scope; from scry.ingestion.source_registry import SourceRegistry; \
import asyncio; \
\
def _sync(): \
    with session_scope() as s: print(SourceRegistry(s).sync_from_yaml())
_sync()"
docker compose up api
```

Then visit:

- Dashboard: <http://localhost:8000/>
- Search UI: <http://localhost:8000/ui/search>
- Review queue: <http://localhost:8000/ui/reviews>
- API docs: <http://localhost:8000/docs>

### AI Search (built-in local LLM)

Ask natural-language questions over your collected intel — grounded answers
with `[n]` citations linking back to the records used. The model runs
**embedded in Scry** (llama.cpp, GGUF): no server, no cloud, no API keys,
nothing leaves the machine.

```bash
pip install -e ".[ai]"          # llama-cpp-python inference engine
scry ai-setup                   # downloads the model (~1 GB, resumes if interrupted)
uvicorn scry.main:app --reload  # then open /ui/search
```

The AI Search panel is **on by default** — until the model is downloaded it
shows setup instructions instead of the question box. Set
`CTI_ENABLE_AI_SEARCH=false` to hide it entirely.

**Bring your own model**: a provider picker on the Search page switches the
answer engine between the bundled local GGUF, an [Ollama](https://ollama.com)
server, and frontier APIs (OpenAI / Anthropic / Google / xAI). Keys are
encrypted at rest and only shown masked; exactly one provider is active at a
time, falling back to the bundled model when none is configured.

- Default model: **Qwen2.5-1.5B-Instruct Q4_K_M** (~1.0 GB on disk, ~2 GB RAM
  at runtime — comfortable on 8 GB machines). A larger alternative is
  Llama-3.2-3B Q4 (~2 GB); download its GGUF and set `CTI_AI_SEARCH_MODEL_PATH`.
- The **first question loads the model (~10s)**; later answers are faster.
- The Search page has an **on-page toggle** (persisted per browser) that
  disables the assistant entirely — zero requests, zero RAM.

### CLI cheat sheet

```bash
scry init-db
scry ingest-url https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-001
scry ingest-source "CISA Advisories"
scry ingest-all
scry search "ransomware"
scry semantic-search "Microsoft RCE exploited in the wild"
scry report daily
scry report weekly
scry sources list
scry sources test
scry reviews list
scry alerts list
scry decay run
scry stats
```

## Configuration

| Knob | File | Default | Purpose |
| --- | --- | --- | --- |
| Sources | `config/sources.yaml` | Vendor blogs + CISA + ISC + Reddit (most aggregators disabled) | Add/remove sources without code changes |
| Watchlists | `config/watchlists.yaml` | Microsoft / ransomware / wipers / DIB / AI / AppDomainManager / KEV / PoC / OT | Topics that drive tagging + scoring + alerts |
| PIRs | `config/pirs.yaml` | 10 default Priority Intelligence Requirements | Article → PIR mapping for reporting |
| Collection policies | `config/policies.yaml` | `safe_public_web`, `public_social_metadata`, `metadata_only`, `passive_metadata_only`, `high_risk_disabled` | What kinds of fetching are allowed for each source |
| Aliases | `config/aliases.yaml` | Conservative APT / ransomware / malware aliases | Canonical-name resolution |
| Env vars | `.env` (see `.env.example`) | All risky knobs default to false | Toggle dark web, file downloads, outbound alerts, LLM provider |

### API authentication

All REST endpoints (`/api/*`, plus the api_router routes such as `/health`, `/articles`, `/stats`) accept an optional static API token. Set it in `.env`:

```bash
CTI_API_KEY=change-me-long-random-string
```

When `CTI_API_KEY` is empty (the default), every endpoint stays open — behavior is unchanged. When set, clients must pass the key on every request via either header:

```bash
curl -H "X-API-Key: change-me-long-random-string" http://localhost:8000/articles
curl -H "Authorization: Bearer change-me-long-random-string" http://localhost:8000/articles
```

The key is compared in constant time; wrong or missing keys get `401` with a `WWW-Authenticate: Bearer` challenge. Exemptions that stay unauthenticated even with a key set: `/health` (monitoring) and `/api/ai/status` + `/api/ai/provider` (the Search-page provider picker). The HTML UI routes (`/ui/*`, dashboard) are never authenticated — if you expose Scry on a network, put the UI behind a reverse proxy or SSO instead.

### MCP server (AI clients)

Scry can expose its intel database directly to AI clients — [Claude Desktop](https://claude.com/download), [Cursor](https://cursor.com), anything that speaks the [Model Context Protocol](https://modelcontextprotocol.io) — over stdio, no HTTP involved. Six tools: `scry_health`, `scry_stats`, `scry_search`, `scry_observables`, `scry_alerts`, and `scry_ask` (grounded LLM Q&A, same pipeline as the Search page).

```bash
pip install scry[mcp]   # adds the official `mcp` package
scry mcp                # serves MCP over stdio
```

Then register the server in your client's config (Claude Desktop: `claude_desktop_config.json`; Cursor: Settings → MCP). Use the module entry point with the venv's Python:

```json
{
  "mcpServers": {
    "scry": {
      "command": "/path/to/cti-enrichment-agent/.venv/bin/python",
      "args": ["-m", "scry.mcp_server"]
    }
  }
}
```

(`scry mcp` as the command works too if the `scry` console script is on the client's PATH.)

Notes:

- **MCP bypasses HTTP API-key auth** — the server is process-local and reads the same SQLite file as the web app, so `CTI_API_KEY` does not apply. Only configure it for clients you trust on this machine.
- **stdout must stay clean** — MCP speaks JSON-RPC on stdout, so scry logs to stderr when running as an MCP server. Any library printing to stdout at import time would break the protocol.
- `scry_ask` uses whichever LLM provider is active (Search page → provider picker); with none configured it returns a graceful error instead of an answer.

## STIX 2.1 & TAXII

scry exports **spec-valid STIX 2.1** bundles (`scry/exports/stix21.py`) and serves them over a minimal **read-only TAXII 2.1** server so other tools (MISP, OpenCTI, Microsoft Sentinel) can consume scry intel. All object ids are deterministic (`uuid5` in a fixed scry namespace), so re-exports are stable and diffable.

**Export endpoint** (same auth as the rest of the API when `CTI_API_KEY` is set):

```bash
# Entities + observable indicators (with SCOs) + relationships
curl -X POST http://localhost:8000/exports/stix21 \
  -H "X-API-Key: $CTI_API_KEY" -H "Content-Type: application/json" \
  -d '{"collection": "intel", "limit": 500}' -o intel-bundle.json

# Report SDOs for recent articles
curl -X POST http://localhost:8000/exports/stix21 \
  -H "X-API-Key: $CTI_API_KEY" -H "Content-Type: application/json" \
  -d '{"collection": "articles"}' -o articles-bundle.json
```

**TAXII 2.1 server** (mounted at `/taxii2`, requires the API key when configured — no discovery exemption):

```bash
curl http://localhost:8000/taxii2/ -H "X-API-Key: $CTI_API_KEY"          # server discovery
curl http://localhost:8000/taxii2/api-root/collections/ -H "X-API-Key: $CTI_API_KEY"
curl 'http://localhost:8000/taxii2/api-root/collections/intel/objects/?limit=100' \
  -H "X-API-Key: $CTI_API_KEY"
```

Two collections are offered: `intel` (entities + observables + relationships) and `articles` (report SDOs). The objects endpoint paginates with `?limit=` and `?next=` and returns TAXII envelopes (`more` / `next` / `objects`).

**Pointing other tools at it:**

- **OpenCTI** — add a TAXII 2.1 feed connector: URL `http://<host>:8000/taxii2`, API root `api-root`, collection `intel`, auth = your `CTI_API_KEY`.
- **MISP** — add a TAXII 2.1 server (Owner Org → TAXII servers): discovery URL `http://<host>:8000/taxii2/`, key as the API key/password; or just import the `POST /exports/stix21` bundle JSON directly.
- **Sentinel / Microsoft Defender TI** — use a TAXII 2.1 data connector pointed at the same discovery URL.

Object-type mapping: scry entity types `threat_actor` / `malware_family` / `campaign` / `intrusion_set` / `tool` become the matching STIX SDOs; `organization` / `person` / `sector` become `identity`; `location` and `vulnerability` map directly; everything else is skipped. Observables of type `ipv4` / `ipv6` / `domain` / `url` / `email` become an `indicator` SDO (with a STIX pattern) plus the matching SCO (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`); hash observables become `[file:hashes ...]` indicators plus a `file` SCO. Relationship types are hyphenated (`uses`, `attributed-to`, …).

## How scoring works

See [`SCORING.md`](./SCORING.md). Highlights:

- **Source reliability** = `baseline + historical_accuracy_adj − fp_rate_penalty − sensationalism_penalty + original_research_bonus − aggregator_penalty` (0–100).
- **Confidence** is a weighted blend of source / extraction / maliciousness / attribution / enrichment / relationship confidence, with a corroboration bonus for multiple **independent** sources (aggregators don't count).
- **Risk** is a transparent contributor list. KEV/RW/MS/PoC/DIB topics add weight; benign-shared-infrastructure / cloud / URL-shortener flags subtract. Final actionability is one of `urgent_review` / `block_if_safe` / `high_priority_hunt` / `monitor` / `enrich_only`.
- **Lifecycle / decay**: IPv4 21d, domain 60d, URL 30d, hashes 365d, CVE/ATT&CK never expire. Cloud-shared hosts decay in 5d.

## Architecture

See [`ARCHITECTURE.md`](./ARCHITECTURE.md). At a glance:

```
sources.yaml ─▶ SourceRegistry ─▶ CollectionPolicyEngine ─▶ SafeFetcher (SSRF guard)
                                                                │
                       feedparser ◀──────────────────────────── ▼
                            │                              article_parser
                            ▼                                   │
                       IngestionEngine ─▶ Article ─▶ Redactor ─▶ Extractor (IOCs, entities, claims, relationships, classifiers, LLM hook)
                                                                │
                                              EnrichmentEngine ◀┘
                                                                │
                                                            Scoring (confidence / risk / decay)
                                                                │
                                                  Persistence + ReviewQueue + Conflicts + Clustering
                                                                │
                                                FastAPI + UI + CLI + Reports + Exports + Alerts
```

## Screenshots

Coming soon — the UI is a server-rendered dark/light themed web app (dashboard, observables, review queue, intel feeds). See [`docs/ui-guide.md`](./docs/ui-guide.md) for a page-by-page walkthrough in the meantime.

## Documentation

| Doc | Contents |
| --- | --- |
| [docs/installation.md](./docs/installation.md) | Prerequisites, venv, editable install, Docker, Postgres vs SQLite, migrations |
| [docs/configuration.md](./docs/configuration.md) | Every `CTI_*` env var and every `config/*.yaml` file explained |
| [docs/usage-cli.md](./docs/usage-cli.md) | Every `scry` CLI command with options and examples |
| [docs/ui-guide.md](./docs/ui-guide.md) | Walkthrough of every UI page, bulk actions, theme toggle |
| [docs/api-reference.md](./docs/api-reference.md) | REST endpoints, parameters, response models |
| [docs/development.md](./docs/development.md) | Repo layout, tests, lint/format, extending Scry |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Module map and end-to-end data flow |
| [DATA_MODEL.md](./DATA_MODEL.md) | Tables and relationships |
| [SCORING.md](./SCORING.md) | Confidence / risk / decay model |
| [SECURITY.md](./SECURITY.md) | Defensive-use safety boundaries |
| [SOURCES.md](./SOURCES.md) | Source registry fields and policies |
| [CONNECTORS.md](./CONNECTORS.md) | Third-party enrichment connectors |
| [INTEGRATIONS.md](./INTEGRATIONS.md) | Integration configuration guide |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to contribute |
| [CHANGELOG.md](./CHANGELOG.md) | Release history |

## Tests

```bash
pytest -q
```

97 tests cover: defang / refang, IOC extraction with FP guardrails, topic classifiers, SSRF guard, collection policy fail-closed defaults, claim and relationship extraction, scoring, IOC decay, alias resolution, secret redaction, dedup, review routing (incl. bulk actions), conflicts, source registry, end-to-end pipeline, full-text + semantic search, API smoke tests, UI routes (incl. timeago filter and flash messages), and an evaluation harness that prevents silent extractor regressions.

## Known limitations

- LLM extraction is stubbed. The hooks exist; deterministic extractors carry the load.
- Enrichers are offline. Passive DNS / WHOIS / certificate transparency / VirusTotal / EPSS integrations are wired as future-pluggable interfaces but not implemented.
- Semantic search uses a deterministic hash embedding so it works with zero infra. A `pgvector` adapter can replace `embed()` in `scry/search/semantic.py`.
- Connectors (MISP, OpenCTI, SIEMs) are stubs that report dry-run status.
- The MVP runs against Postgres+pgvector via Docker, and uses SQLite as a fallback for local / test runs. Alembic builds the schema from SQLAlchemy metadata.
- Sigma / YARA / KQL generators are scaffolded as a `Detection` table; auto-generation logic is intentionally absent — generated detections must be marked as such and validated by a human.

## Roadmap

- Replace the hash embedding with `pgvector` + a real model.
- Plug in passive DNS / WHOIS / VirusTotal / EPSS enrichers behind the existing `BaseEnricher` interface.
- Implement Sigma / YARA / Suricata generators with FP-rate guardrails.
- Internal telemetry sightings (DNS, proxy, EDR) — the schema and connector interface are already in place.

## License

Apache 2.0 — see [LICENSE](./LICENSE). Copyright altered-intelligence.
