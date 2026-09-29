# Changelog

All notable changes to Scry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
semantic versioning.

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
