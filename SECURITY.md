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
