# Scoring

All scores are 0–100. Every score is reproducible from the inputs and exposes a contributor breakdown so analysts can see *why* it is what it is.

## Source reliability — `scry/scoring/source_reliability.py`

```
score = baseline
      + (historical_accuracy − 0.75) × 40
      − (false_positive_rate − 0.10) × 50
      − sensationalism_score × 10
      + 10 if original_research_ratio > 0.7
      − 10 if is_aggregator
```

Clamped to [0, 100]. Defaults come from `config/sources.yaml` `baseline_confidence`; analyst feedback updates `historical_accuracy` and `false_positive_rate`.

## Confidence — `scry/scoring/confidence.py`

Weighted blend with corroboration bonus:

```
overall = source_confidence       × 0.30
        + extraction_confidence   × 0.25
        + maliciousness           × 0.20
        + attribution             × 0.10
        + enrichment              × 0.10
        + relationship            × 0.05
        + corroboration_bonus  (min(20, (independent_sources − 1) × 5))
        − 5 if aggregator-only sources
```

Rationale strings are returned so the UI can show *why* the bonus or penalty applied.

## Risk — `scry/scoring/risk.py`

Transparent contributor list. Every contributor is named so a UI can render the breakdown:

```
base = maliciousness × 0.4 + source_confidence × 0.2
     + (recency_days ≤ 7  → +10  | recency_days > 180 → −15)
     + (independent_sources ≥ 2 → +10)
     + topic contributors:
        ransomware             → +20
        wiper                  → +20
        exploited-in-the-wild  → +25
        defense-industry       → +15
        microsoft              → +10
        exploit-poc            → +10
        appdomainmanager-hij…  → +10
        ai-security            → +5
     + enrichment contributors:
        kev                       → +25
        ransomware_associated     → +15
        public_poc_available      → +10
     + benign-context penalties:
        benign-shared-infra       → −20
        likely_cloud_or_cdn       → −10
        url_shortener             → −10
```

Clamped to [0, 100]. Actionability buckets:

| Score | Actionability |
| --- | --- |
| ≥ 85 | `urgent_review` |
| 70–84 | `block_if_safe` |
| 55–69 | `high_priority_hunt` |
| 30–54 | `monitor` |
| < 30 | `enrich_only` |

If any benign-context flag is set, actionability is forced to `monitor` regardless of score.

## Lifecycle / decay — `scry/scoring/lifecycle.py`

Default TTLs by indicator type:

| Type | TTL | Rationale |
| --- | --- | --- |
| ipv4 / ipv6 | 21d | Adversary infrastructure rotates fast |
| domain | 60d | Domains live longer than IPs |
| url | 30d | |
| email | 90d | |
| md5 / sha1 / sha256 / sha512 / ssdeep / tlsh | 365d | Hashes are brittle for detection but valuable in history |
| registry_key / named_pipe | 365d | |
| attack_technique / cve / asn | ∞ | Never expires |
| onion | 30d | |
| wallet_* | 365d | |
| telegram_handle | 90d | |
| discord_invite | 30d | |

Cloud-hosted observables (`likely_cloud_or_cdn=true` in enrichment) are overridden to **5d** to prevent shared-infrastructure recommendations from lingering.

Expired observables stay searchable but are **never block-recommended**.

## Hallucination controls

No LLM-generated claim is persisted unless its `evidence_text` is present in the source. The pipeline validates this before commit. See `scry/extraction/llm/` and `scry/pipeline.py`.

## Audit

The full input set used to compute a score is reproducible from the persisted row — `scoring_model_version` identifies which version of the algorithm produced the number. When the model changes, bump the version constant in `scry/scoring/__init__.py`.
