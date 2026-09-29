# Development

## Repository layout

```
scry/                     # Python package (was cti_agent pre-rebrand)
├── config.py             # pydantic-settings, env prefix CTI_ (legacy, intentional)
├── db.py                 # SQLAlchemy engine + session factory
├── main.py               # FastAPI app, UI routes, Jinja setup, timeago filter
├── cli.py                # `scry` CLI (Typer)
├── pipeline.py           # Article → extract → enrich → score → persist → review
├── scheduler.py          # APScheduler recurring jobs
├── ingestion/            # SSRF guard, policy engine, fetcher, RSS/KEV, registry
├── parsing/              # article parser, normalizer, secret redactor
├── extraction/           # IOC/entity/claim/relationship extractors, classifiers, LLM hook
├── enrichment/           # infrastructure, URL, email, CVE, ATT&CK, prevalence, VT/OTX
├── scoring/              # source reliability, confidence, risk, lifecycle/decay
├── models/               # SQLAlchemy 2.x models (30+ tables)
├── schemas/              # Pydantic API schemas
├── api/router.py         # REST API
├── ui/templates/         # Jinja2 templates (base.html holds all CSS)
├── review/ review queue  # routing + queue helpers
├── alerting/             # alert engine + channels (off by default)
├── reporting/            # daily/weekly Markdown reports
├── exports/              # JSON / CSV / STIX-like
├── search/               # full-text + offline hash-embedding semantic search
└── connectors/           # MISP / OpenCTI dry-run stubs
tests/                    # pytest, asyncio_mode=auto, per-test isolated SQLite
config/                   # sources / watchlists / pirs / policies / aliases YAML
alembic/                  # migrations
docs/                     # this documentation set
scripts/                  # ad-hoc operational scripts
```

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest -q        # 97 tests
```

Tests run against per-test isolated SQLite databases (see
`tests/conftest.py`); nothing external is required. `respx` mocks HTTP,
`freezegun` is available for time-sensitive tests. `tests/test_eval_harness.py`
guards against silent extractor regressions — extend it when you change
extractor behavior intentionally.

## Lint, format, typecheck

```bash
ruff check .                 # lint (config in pyproject.toml)
black --check .              # format check; run `black .` to apply
mypy scry                    # optional; configured non-strict
make lint / make format      # convenience wrappers
```

Code style: line length 110, target Python 3.11. Ruff rule sets: E, F, I, B,
UP, SIM, RUF. Docstring-first modules; keep the defensive-by-default posture.

## UI changes

All CSS lives in `base.html` as CSS variables with a `[data-theme="light"]`
override block — never hardcode colors; both themes must stay readable.
Timestamps go through the `timeago` Jinja filter (registered in `main.py`).
Mutating UI actions redirect with `?flash=…&flash_kind=…` (see
`_redirect_flash` in `main.py`).

## Adding a source

1. Add an entry to `config/sources.yaml` (see [SOURCES.md](../SOURCES.md) for
   field semantics) — choose the least-permissive collection policy that works.
2. `scry init-db` to sync (or just restart the app; startup syncs too).
3. `scry sources test` to dry-run the policy + SSRF checks.

## Adding a collector

Implement the fetch/parse path behind the existing ingestion interfaces
(`scry/ingestion/`). New fetch behavior must pass through the
`CollectionPolicyEngine` (fail-closed) and the SSRF guard — never bypass them.

## Adding an enricher

Implement `BaseEnricher.enrich(value, context)` (`scry/enrichment/base.py`),
register it in `EnrichmentEngine` (`scry/enrichment/engine.py`), set
`requires_network` honestly, and cache/rate-limit external calls like the
VirusTotal/OTX enrichers do. Add tests.

## Conventions worth knowing

- Every persisted derived object records `extractor_version` /
  `scoring_model_version` — bump when behavior changes.
- No LLM-generated claim may be stored without evidence text.
- Outbound alerting, dark web, JS rendering, and file downloads must remain
  opt-in settings that default off (see [SECURITY.md](../SECURITY.md)).

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution workflow.
