# Sources

Sources live in `config/sources.yaml`. Each entry is loaded into the `sources` table on `scry init-db`. Every source has:

- `name` (unique)
- `type` — `vendor_blog`, `news`, `vuln_feed`, `reddit`, `research`, `aggregator`, `newsletter`, `github_repo`, `onion`
- `url` — canonical source URL
- `feed` — optional RSS/Atom/JSON feed URL
- `enabled` — defaults false for risky / aggregator sources
- `priority` — high / medium / low
- `baseline_confidence` — 0-100
- `collection_policy` — name of a policy in `config/policies.yaml`
- `safety_mode` — optional override (e.g. `passive_only` for onion)
- `independent` — whether this counts toward corroboration (aggregators are false)
- `rate_limit_per_minute`
- `tags`
- `notes`

## Default sources

| Source | Type | Default | Confidence | Independent | Notes |
| --- | --- | --- | --- | --- | --- |
| CrowdStrike Blog | vendor_blog | **enabled** | 92 | ✓ | |
| Fortinet Threat Research | vendor_blog | **enabled** | 92 | ✓ | |
| Palo Alto Unit 42 | vendor_blog | **enabled** | 93 | ✓ | |
| Check Point Blog | vendor_blog | **enabled** | 88 | ✓ | |
| SecurityWeek | news | **enabled** | 80 | ✗ | |
| The Hacker News | news | **enabled** | 70 | ✗ | Aggregator-ish |
| BleepingComputer | news | **enabled** | 82 | ✗ | |
| Dark Reading | news | **enabled** | 78 | ✗ | |
| The Record | news | **enabled** | 80 | ✗ | |
| Ars Technica Security | news | **enabled** | 75 | ✗ | |
| CISA KEV | vuln_feed | **enabled** | 98 | ✓ | JSON, drives MS / KEV alerts |
| CISA Advisories | vuln_feed | **enabled** | 97 | ✓ | |
| SANS ISC | research | **enabled** | 90 | ✓ | |
| Reddit /r/netsec | reddit | **enabled** | 60 | ✗ | Public RSS only |
| Reddit /r/cybersecurity | reddit | **enabled** | 55 | ✗ | Public RSS only |
| NVD CVE Feed | vuln_feed | disabled | 95 | ✓ | Needs API key for rate limits |
| CVEmon | vuln_feed | disabled | 75 | ✗ | |
| NewsNow Cybersecurity | aggregator | disabled | 40 | ✗ | Pure aggregator |
| TLDR Tech | newsletter | disabled | 55 | ✗ | |
| Cybersec Stats | aggregator | disabled | 45 | ✗ | |
| start.me InfoSec | aggregator | disabled | 40 | ✗ | Link directory |
| GitHub awesome-osint | github_repo | disabled | 60 | ✗ | Source directory, *not* auto-clone |
| Passive Dark Web Sources | onion | **disabled** | 35 | ✗ | `passive_metadata_only`; gated by `CTI_ENABLE_DARK_WEB` |

## Adding a source

```yaml
# config/sources.yaml
sources:
  - name: My Custom Vendor Feed
    type: vendor_blog
    url: https://example.com/blog
    feed: https://example.com/blog/feed.xml
    enabled: true
    priority: medium
    baseline_confidence: 75
    collection_policy: safe_public_web
    independent: true
    rate_limit_per_minute: 10
    tags: [vendor, custom]
```

Then run:

```bash
scry init-db   # idempotent — re-syncs YAML into the DB
```

## Aggregator handling

Aggregators (`type: aggregator`, `type: newsletter`, or `independent: false`) get a -5 confidence penalty and **do not contribute to corroboration counts**. Two aggregator hits on the same IOC still count as one independent source.
