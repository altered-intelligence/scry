# Security model

This system is for defensive cyber threat intelligence work only.

## Hard-coded prohibitions

These are enforced in code (`config/policies.yaml` → `prohibited_actions`) and **cannot be enabled by configuration**:

- authenticate_to_criminal_services
- collect_stolen_credentials
- collect_victim_data_dumps
- purchase_or_validate_illicit_data
- interact_with_threat_actors
- bypass_authentication_or_captchas
- bypass_robots_txt
- exploit_vulnerabilities
- execute_malware_or_exploits
- download_malware_samples
- clone_exploit_repositories
- submit_forms_to_suspicious_sites
- active_scanning_third_party_systems

## Safe defaults (env-controlled)

All knobs default to the conservative side. Explicit opt-in required to flip:

| Setting | Default | Effect when on |
| --- | --- | --- |
| `CTI_ENABLE_DARK_WEB` | `false` | Permits passive metadata-only collection from explicitly-configured `.onion` sources |
| `CTI_ENABLE_JS_RENDERING` | `false` | Allows JS-rendered page fetches (off in MVP regardless) |
| `CTI_ENABLE_FILE_DOWNLOADS` | `false` | Allows non-text responses; still no execution |
| `CTI_ENABLE_EXPLOIT_REPO_CLONE` | `false` | Allows shallow metadata of exploit repos; **never clones** |
| `CTI_ENABLE_OUTBOUND_ALERTS` | `false` | Allows Slack/Teams/webhook delivery |
| `CTI_MAX_FETCH_BYTES` | 5 MiB | Hard size cap |
| `CTI_FETCH_TIMEOUT_SECONDS` | 20 | Hard timeout |

## API authentication

All REST endpoints accept an optional static API token (`CTI_API_KEY` in `.env`, implemented as a FastAPI dependency in `scry/api/auth.py`). When unset, every endpoint is open (single-operator default). When set:

- Clients must send `X-API-Key: <key>` or `Authorization: Bearer <key>`; anything else gets `401` with a `WWW-Authenticate: Bearer` challenge.
- The key is compared with `hmac.compare_digest` (constant time) to avoid timing leaks.
- Exemptions stay unauthenticated so dependent surfaces keep working: `/health` (monitoring probes) and `/api/ai/status` (Search-page status pill). The provider list `/api/ai/provider` requires authentication: it exposes base URLs, masked keys, and connection errors (the Search page sends the session cookie).
- The HTML UI routes (`/ui/*`, dashboard) are **never** authenticated by this token — they are plain FastAPI routes outside the API routers. If Scry is exposed beyond localhost, put the UI behind a reverse proxy / SSO; do not rely on `CTI_API_KEY` to protect browser pages.

## SSRF guard

`scry/ingestion/ssrf.py` runs before every fetch:

- Only `http` and `https` schemes
- Hostname resolved before connecting
- Blocked: loopback, link-local, multicast, private (RFC 1918), reserved, broadcast
- Blocked: AWS/GCP/Azure metadata endpoints
- Blocked: explicit denylist hosts from `config/policies.yaml`
- `.onion` hosts: blocked unless `CTI_ENABLE_DARK_WEB=true`

## Collection policy engine

`CollectionPolicyEngine` translates per-source policy names into a single decision object (`allowed`, `fetch_mode`, `allow_javascript`, `allow_file_download`, `respect_robots_txt`, `max_depth`, `requires_analyst_approval`, `safety_mode`). Unknown / malformed policies fail closed.

Predefined policies in `config/policies.yaml`:

- `safe_public_web` — public web pages, RSS, vendor blogs
- `public_social_metadata` — Reddit, public social via RSS/API only
- `metadata_only` — GitHub repos, app stores; no source/binary downloads
- `passive_metadata_only` — onion / dark-web; **disabled by default**
- `high_risk_disabled` — paste sites, leak sites, exploit drops, criminal forums; **always denied**

## Secret redaction

`scry/parsing/redactor.py` strips:

- AWS access keys / AWS secret-shaped strings
- GitHub PATs, Slack tokens, Google API keys
- JWT bearer tokens
- RSA / EC / OpenSSH / DSA private-key blocks
- `password|passwd|pwd|api_key|secret` assignments
- `Authorization: Bearer` headers
- Session cookies (`session=`, `sessionid=`, `jsessionid=`, `phpsessid=`)

Redaction runs **before** article text is committed to the DB and before any search index sees it.

## Benign-context guardrails

`config/policies.yaml` lists hosts that must never be naively block-recommended:

- microsoft.com, office365.com, sharepoint.com, outlook.com
- github.com / githubusercontent.com
- google.com / googleapis.com / gstatic.com
- cloudflare.com / cloudflare.net
- amazonaws.com / azure.com / azurewebsites.net / core.windows.net
- discord.com / cdn.discordapp.com / telegram.org / t.me
- bit.ly / tinyurl.com / goo.gl

When an extracted observable resolves to one of these, the extractor tags it `benign-shared-infrastructure`, the risk scorer subtracts 20+ points, and (if a high-confidence claim would otherwise demand blocking) the item is routed to the analyst review queue rather than auto-actioned.

## Data flows

What leaves the machine, and when. Nothing else is sent anywhere.

| Data | Destination | When |
| --- | --- | --- |
| Feed/page requests | the configured sources | scheduled or manual collection (SSRF-guarded, policy-checked) |
| Indicator values (IP, domain, URL, hash) | VirusTotal, OTX, AbuseIPDB, GreyNoise, FortiGuard | only for providers with a key configured, during enrichment runs or a user's live lookup |
| CVE IDs | FIRST.org EPSS API (keyless) | EPSS enrichment runs |
| Domain names | crt.sh certificate-transparency search (keyless, passive) | passive-DNS enrichment runs |
| AI Search question + top matching excerpts | the selected AI provider | only when a hosted provider (OpenAI, Anthropic, …) is configured; the bundled local model never leaves the machine, Ollama goes wherever its base URL points (localhost by default) |
| Alerts | Slack / Teams / webhook / SMTP | only with `CTI_ENABLE_OUTBOUND_ALERTS=true` and a channel configured |

Searches, analyst comments, review decisions, watchlists and user accounts
stay in the local database. Stored page HTML is pruned after
`CTI_RAW_HTML_RETENTION_DAYS` (default 30); `scry backup` / `scry restore`
cover recovery.

## Third-party data terms

Check each provider's terms before using Scry commercially or sharing its
output with clients:

- **VirusTotal**: the free public API may not be used in commercial
  products or services; a commercial deployment needs a VirusTotal premium
  licence.
- **Other enrichment providers** (OTX, AbuseIPDB, GreyNoise, FortiGuard,
  FIRST.org EPSS, crt.sh): free tiers often restrict commercial use,
  volume, or redistribution — confirm the licence that matches your use.
- **Collected articles and imported feeds** (e.g. ransomware leak-site
  trackers) remain their publishers' content: keep attribution (Scry tags
  every item `source:<name>`) and respect redistribution terms when quoting
  them in client deliverables.

## What the LLM is allowed to do

- Summarize an article
- Suggest claims, **always with evidence text the validator can match back to the source**

What it cannot do:

- Invent IOCs, CVEs, malware names, or attribution that don't appear in the source text or in a trusted enrichment source
- Have its output stored without Pydantic validation
- Override deterministic extractor results

## Audit logging

`scry/audit.py` writes every source change / ingestion run / review update to the `audit_logs` table. Schema: `actor`, `action`, `target_type`, `target_id`, `detail` JSON.

## Reporting safety controls

Daily and weekly reports include a **confidence legend** and explicitly:

- distinguish confirmed / likely / possible
- list items flagged for human review
- list collection gaps (failed fetches in the window)
- avoid over-attribution

## Responsible disclosure

If you find a security issue in this project, please report privately via a private security advisory on the source repo rather than filing a public issue.
