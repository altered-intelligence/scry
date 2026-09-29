# UI guide

Scry's web UI is server-rendered (Jinja2 templates, no JavaScript framework).
Start it with `uvicorn scry.main:app --reload` and open
<http://localhost:8000/>. The schema self-initializes on startup.

## Navigation

The header contains: the **Scry** brand (with the tagline *"Seeing threats
before they arrive"*), an **Intel** dropdown (Articles, Observables, CVEs,
Entities, Tags, Sources), top-level **Reviews** and **Alerts**, an **Intel
Feeds** dropdown (Threat Feeds, Ransomware Feeds), **Search**, and a link to
the **API** docs. On the right: a defensive-use notice and the theme toggle.

## Themes

The ☾/☀ button in the header switches between the dark (GitHub-dark-inspired)
and light (GitHub-light-inspired) themes. The choice persists in
`localStorage` and defaults to your OS `prefers-color-scheme`. A pre-paint
inline script prevents any flash of the wrong theme, and transitions are
disabled when `prefers-reduced-motion` is set.

## Flash messages

Actions that mutate state (bulk review disposition, collection runs, review
saves) redirect with `?flash=…&flash_kind=success|error`. The banner renders
at the top of the page and dismisses with the × button.

## Pages

### Dashboard (`/`)

Stat cards (articles, observables, CVEs, threat-feed items, ransomware-feed
items, open reviews), a **Collect now** button (POSTs `/ui/ingest/run`, runs
the same ingestion path as the API, then redirects with a summary flash) with
a **Last collected** freshness line, high-risk observables, recent articles,
recent high-risk threat-feed items, a safety-defaults sidebar, and quick
links (including "Manage sources").

### Articles (`/ui/articles`, `/ui/articles/{id}`)

Full-text/tag filterable article list with pagination. The detail page shows
metadata (published/ingested as relative times, hover for absolute), tags,
extracted observables and entities (with evidence), and claims.

### Observables (`/ui/observables`, `/ui/observables/{id}`)

Filter by text, type, tag, minimum risk, status. Rows show type chip, value,
risk badge, actionability badge, and tags. The detail page shows mentions
(evidence per article), relationships in both directions, enrichment cards
(VirusTotal / OTX when configured), and the raw enrichment JSON.

### CVEs (`/ui/cves`, `/ui/cves/{cve_id}`)

Filter by text, vendor, severity, KEV-only, Microsoft-only. Detail page shows
CVE metadata and articles mentioning it.

### Entities (`/ui/entities`, `/ui/entities/{id}`)

Threat actors, malware families, tools, campaigns, etc. with type/tag/text
filters. The detail page resolves related entities and observables and lists
mentioning articles.

### Tags (`/ui/tags`, `/ui/tags/{tag}`)

A size-bucketed tag cloud across observables, articles, and entities; tag
detail pages list everything carrying that tag.

### Sources (`/ui/sources`)

The source registry: a summary strip (total / enabled / disabled) and a table
with name (external link), type chip, enabled badge, priority, baseline
confidence, collection policy, rate limit, tags, and expandable notes. Synced
from `config/sources.yaml` at startup / `scry init-db`.

### Reviews (`/ui/reviews`, `/ui/reviews/{id}`)

The analyst review queue. The list supports status/item-type filters, an
expandable Reason column (click the truncated text), and **bulk actions**:
tick rows (or the header select-all), choose *Approve (true positive)* or
*Reject (false positive)*, and apply — matching open reviews are closed with
that disposition in one transaction, with a confirmation flash. The detail
page offers full disposition editing (status, disposition vocabulary:
`true_positive`, `false_positive`, `benign`, `duplicate`,
`needs_more_research`, `escalated`, `mitigated`, `expired`), analyst name,
comments, and correction JSON.

### Alerts (`/ui/alerts`)

Alerts produced by the alert engine (KEV additions, Microsoft exploited CVEs,
high-risk observables, ransomware reporting). Outbound delivery is off unless
`CTI_ENABLE_OUTBOUND_ALERTS=true`.

### Intel Feeds

- **Threat Feeds** (`/ui/intel-feeds/threat-feeds`) — collected threat-feed
  items with text/category/network/country filters, sorting, and
  network-aware chips (Telegram / Tor).
- **Ransomware Feeds** (`/ui/intel-feeds/ransomware-feeds`) — ransomware
  victim posts with group/country/industry filters and related-victim linking.

### Search (`/ui/search`)

Full-text search across articles, observables, entities, and claims with
deep links into each detail page.

When `CTI_ENABLE_AI_SEARCH=true`, an **AI Search** panel appears below the
results: ask natural-language questions and get grounded answers from a local
model embedded in Scry (no cloud calls). Answers cite the records used as
`[1]`, `[2]`, … and each citation links to the record's detail page. A status
pill shows whether the model file is present; a per-browser toggle switch
disables the assistant entirely (no requests, no RAM used). Setup:
`pip install -e ".[ai]"` + `scry ai-setup`. The first question loads the
model into memory (~10s).

## Timestamps

All timestamps render as relative times ("3h ago", "2d ago") in a `<time>`
element; hover for the absolute UTC time.

---

Back to [README](../README.md) · [api-reference.md](./api-reference.md)
