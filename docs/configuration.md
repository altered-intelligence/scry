# Configuration

Scry is configured through environment variables (with an optional `.env`
file) plus five YAML files in `config/`. All settings are defined in
`scry/config.py` (`Settings`) and loaded via `get_settings()`.

> **Legacy prefix:** the env prefix is `CTI_` (kept from the project's
> original name so existing `.env` files keep working). All variables below
> are shown with that prefix.

Copy `.env.example` to `.env` to get a fully commented starting point.
Every risky capability defaults to **off**.

## Environment variables

### Core

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_ENV` | `local` | Environment label (`local` / `test` / `prod`). |
| `CTI_LOG_LEVEL` | `INFO` | Structlog level. |
| `CTI_DATABASE_URL` | `sqlite+pysqlite:///./cti.sqlite` | SQLAlchemy database URL. Use `postgresql+psycopg://…` for Postgres. |
| `CTI_API_HOST` | `0.0.0.0` | Bind host (reference value; uvicorn flags also work). |
| `CTI_API_PORT` | `8000` | Bind port (reference value). |

### Safety guardrails (all default off)

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_ENABLE_DARK_WEB` | `false` | Allow onion / dark-web sources (passive metadata only, even then). |
| `CTI_ENABLE_JS_RENDERING` | `false` | Allow JavaScript rendering during fetch. |
| `CTI_ENABLE_FILE_DOWNLOADS` | `false` | Allow downloading files/binaries referenced by sources. |
| `CTI_ENABLE_EXPLOIT_REPO_CLONE` | `false` | Allow cloning exploit repositories. |
| `CTI_ENABLE_OUTBOUND_ALERTS` | `false` | Master switch for Slack/Teams/webhook alert delivery. |
| `CTI_MAX_FETCH_BYTES` | `5242880` (5 MB) | Per-fetch response size cap. |
| `CTI_FETCH_TIMEOUT_SECONDS` | `20` | HTTP fetch timeout. |

### LLM & UI

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_LLM_PROVIDER` | `stub` | `stub` (offline, no network) or `anthropic`. The stub does no work; deterministic extractors carry the load. |
| `CTI_ENABLE_AI_SEARCH` | `false` | Show the experimental AI chat panel on `/ui/search`. Requires LLM provider assets; off by default. |

### Retention

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_RETENTION_RAW_HTML_DAYS` | `14` | Days to keep raw fetched HTML. |
| `CTI_RETENTION_ARTICLE_TEXT_DAYS` | `365` | Days to keep extracted article text. |

### Alert channels (inert unless `CTI_ENABLE_OUTBOUND_ALERTS=true`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_SLACK_WEBHOOK_URL` | _(empty)_ | Slack incoming-webhook URL. |
| `CTI_TEAMS_WEBHOOK_URL` | _(empty)_ | Microsoft Teams webhook URL. |
| `CTI_ALERT_EMAIL_FROM` | _(empty)_ | From address for email alerts. |
| `CTI_ALERT_EMAIL_TO` | _(empty)_ | Recipient for email alerts. |

### Enrichment providers (off unless key set)

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_VIRUSTOTAL_API_KEY` | _(empty)_ | VirusTotal v3 key. |
| `CTI_OTX_API_KEY` | _(empty)_ | AlienVault OTX key. |
| `CTI_VT_RATE_PER_MIN` | `4` | VirusTotal token-bucket rate (public tier). |
| `CTI_VT_DAILY_QUOTA` | `480` | VirusTotal daily call budget. |
| `CTI_OTX_RATE_PER_SEC` | `8` | OTX rate limit. |
| `CTI_GREYNOISE_API_KEY` | _(empty)_ | GreyNoise key (IP/domain enrichment). |
| `CTI_URLSCAN_API_KEY` | _(empty)_ | urlscan.io key. |
| `CTI_ABUSEIPDB_API_KEY` | _(empty)_ | AbuseIPDB key. |
| `CTI_CENSYS_API_ID` / `CTI_CENSYS_API_SECRET` | _(empty)_ | Censys credentials. |
| `CTI_SHODAN_API_KEY` | _(empty)_ | Shodan key. |
| `CTI_NVD_API_KEY` | _(empty)_ | NVD key (raises CVE API rate limits). |
| `CTI_GITHUB_TOKEN` | _(empty)_ | GitHub token (Advisories API). |

### Threat-intel platforms, SIEM/SOAR, case management (placeholders)

`CTI_MISP_URL`, `CTI_MISP_KEY`, `CTI_MISP_API_KEY`, `CTI_MISP_VERIFY_SSL`,
`CTI_OPENCTI_URL`, `CTI_OPENCTI_KEY`, `CTI_OPENCTI_API_KEY`,
`CTI_OPENCTI_VERIFY_SSL`, `CTI_TAXII_URL`, `CTI_TAXII_USERNAME`,
`CTI_TAXII_PASSWORD`, `CTI_TAXII_VERIFY_SSL`, `CTI_SENTINEL_WORKSPACE_ID`,
`CTI_SENTINEL_API_KEY`, `CTI_SENTINEL_SUBSCRIPTION_ID`,
`CTI_SENTINEL_RESOURCE_GROUP`, `CTI_SPLUNK_URL`, `CTI_SPLUNK_TOKEN`,
`CTI_SPLUNK_VERIFY_SSL`, `CTI_ELASTIC_URL`, `CTI_ELASTIC_API_KEY`,
`CTI_ELASTIC_VERIFY_SSL`, `CTI_THEHIVE_URL`, `CTI_THEHIVE_API_KEY`,
`CTI_THEHIVE_VERIFY_SSL`, `CTI_CORTEX_URL`, `CTI_CORTEX_API_KEY`,
`CTI_CORTEX_VERIFY_SSL` — all default empty/`true`; connectors are dry-run
stubs today (see [CONNECTORS.md](../CONNECTORS.md) and
[INTEGRATIONS.md](../INTEGRATIONS.md)).

### Social media collectors (placeholders)

`CTI_REDDIT_CLIENT_ID`, `CTI_REDDIT_CLIENT_SECRET`, `CTI_TWITTER_BEARER_TOKEN`,
`CTI_BLUESKY_HANDLE`, `CTI_BLUESKY_PASSWORD`, `CTI_MASTODON_INSTANCE`,
`CTI_MASTODON_TOKEN` — all default empty.

### Feedly

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_FEEDLY_API_TOKEN` | _(empty)_ | Feedly API token. |
| `CTI_FEEDLY_USER_ID` | _(empty)_ | Feedly user ID (personal streams). |

### Advanced

| Variable | Default | Purpose |
| --- | --- | --- |
| `CTI_CONFIG_DIR` | `<repo>/config` | Override the YAML config directory. |

## YAML configuration files

### `config/sources.yaml`

The source registry. Each entry: `name`, `type` (free-form label such as
`vendor_blog`, `news`, `vuln_feed`, `aggregator`, `reddit`, `github_repo`,
`onion`), `url`, optional `feed`, `enabled`, `priority` (high/medium/low),
`baseline_confidence` (0–100), `collection_policy` (one of the policies
below), optional `safety_mode`, `independent` (whether the source counts as
independent corroboration), `rate_limit_per_minute`, `tags`, and optional
`notes`. Synced into the `sources` table by `scry init-db` and on app startup.
See [SOURCES.md](../SOURCES.md).

### `config/watchlists.yaml`

Topic watchlists (name, description, keywords, tags) that drive article
tagging, scoring weights, and alert triggers — e.g. Microsoft
vulnerabilities, ransomware, wipers, defense industrial base, AI security,
KEV, proof-of-concept activity, ICS/OT.

### `config/pirs.yaml`

Priority Intelligence Requirements: `id`, `question`, linked `watchlists`,
and `priority`. Used to map articles to PIRs in daily/weekly reports.

### `config/policies.yaml`

Collection policies — the fail-closed gate definitions referenced by
`collection_policy` in sources.yaml: `safe_public_web`,
`public_social_metadata`, `metadata_only`, `passive_metadata_only`,
`high_risk_disabled`. Each defines what fetching behavior is allowed.

### `config/aliases.yaml`

Threat-actor and malware-family alias dictionary (canonical name → aliases,
suspected origin, motivation) used by entity extraction and canonical-name
resolution.

Next: [usage-cli.md](./usage-cli.md) · back to [README](../README.md)
