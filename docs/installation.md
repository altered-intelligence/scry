# Installation

Scry runs as a Python 3.11+ application with either a zero-infrastructure
SQLite backend (local/dev) or Postgres + pgvector (production-ish, via Docker).

## Prerequisites

- **Python ≥ 3.11** (3.12 recommended)
- git
- Optional: Docker + Docker Compose (for the Postgres deployment)
- Optional: `make` (convenience targets in the `Makefile`)

## Local install (SQLite, zero infra)

```bash
git clone https://github.com/altered-intelligence/scry.git
cd scry

python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"      # dev extras: pytest, ruff, black, mypy, respx, freezegun

# SQLite is the default database; you can also pin it explicitly:
export CTI_DATABASE_URL="sqlite+pysqlite:///./cti.sqlite"

scry init-db                 # create schema + sync config/sources.yaml
scry sources list            # verify the source registry
scry ingest-source "CISA Advisories"
scry stats

# Web UI (the app also self-initializes the schema on startup)
uvicorn scry.main:app --reload
```

Open <http://localhost:8000/>.

> **Note on naming:** the environment variable prefix remains `CTI_` and the
> default SQLite file remains `cti.sqlite` for backwards compatibility with
> pre-rebrand deployments. This is intentional.

## Docker (Postgres + pgvector)

```bash
cp .env.example .env         # edit if you want API keys / non-default DB URL
docker compose up -d postgres
docker compose run --rm api alembic upgrade head
docker compose up api
```

The `api` service runs `alembic upgrade head` and then uvicorn on port 8000.
A `scheduler` service (APScheduler recurring jobs) is available under the
`optional` compose profile, as is a `redis` service. For running the
scheduler outside Docker — launchd on macOS (`scry scheduler install`),
systemd on Linux — and the optional daily digest email, see
[scheduling.md](./scheduling.md).

### Image hardening (v0.13.0)

The image is a **multi-stage build**: a `builder` stage installs the pinned
dependency set (`requirements.lock`) into a virtualenv, and the
`python:3.12-slim` runtime stage copies only that venv — no compilers,
headers, or pip caches in the final image. Runtime dependencies are
self-contained wheels (`psycopg[binary]` bundles libpq; cryptography/lxml/
pillow link statically), so the final stage installs zero system packages.

The container runs as a **non-root `scry` user** (uid/gid 1000) with `/app`
as the only writable tree: the SQLite default DB, `.cti_cache/`, and
`reports/` land in the working directory, and the auto-generated Fernet key
is relocated to `/app/data/.cti_secret` via `CTI_SECRET_FILE` (the package
itself sits in read-only site-packages). A `HEALTHCHECK` probes `/health`
every 30 s using python urllib (no curl in the image).

**Persistence:** mount `/app/data` to keep the encryption key across
rebuilds — without it, re-creating the container generates a new key and
previously stored (encrypted) API keys become unreadable. The compose bundle
wires this as the `cti_data` named volume on `api` and `scheduler`. For a
standalone SQLite container:

```bash
docker build -t scry .
docker run -p 8000:8000 -v scry_data:/app/data \
  -e CTI_DATABASE_URL=sqlite+pysqlite:////app/data/cti.sqlite \
  scry
```

**Reproducible builds:** dependencies are pinned by `requirements.lock`
(exact versions, generated from a clean `pip install .`). Refresh after
dependency changes with:

```bash
python3.12 -m venv /tmp/lock && /tmp/lock/bin/pip install . \
  && /tmp/lock/bin/pip freeze | grep -v '^scry' > requirements.lock
```

Endpoints once running:

- Dashboard: <http://localhost:8000/>
- Search UI: <http://localhost:8000/ui/search>
- Review queue: <http://localhost:8000/ui/reviews>
- Source registry: <http://localhost:8000/ui/sources>
- API docs (OpenAPI): <http://localhost:8000/docs>

## Postgres vs SQLite

| | SQLite (default) | Postgres + pgvector |
| --- | --- | --- |
| Setup | none | `docker compose up -d postgres` |
| `CTI_DATABASE_URL` | `sqlite+pysqlite:///./cti.sqlite` | `postgresql+psycopg://cti:cti@localhost:5432/cti` |
| Use for | local dev, tests, demos | production-ish deployments |
| Semantic search | persisted deterministic hash embeddings (offline) | legacy live-embedding path; a pgvector adapter can replace `embed()` in `scry/search/embeddings.py` |

Tests always run against isolated per-test SQLite files; no Postgres is needed
for the test suite.

## Database migrations

Alembic builds the schema from SQLAlchemy metadata:

```bash
alembic upgrade head         # apply migrations (config: alembic.ini, alembic/)
```

For SQLite local runs, `scry init-db` (or app startup) calls
`Base.metadata.create_all`, which is equivalent for a fresh database.

## Verifying the install

```bash
scry --help                  # CLI entry point
pytest -q                    # 97 tests, all should pass
ruff check . && black --check .
```

Next: [configuration.md](./configuration.md) · [usage-cli.md](./usage-cli.md) ·
[ui-guide.md](./ui-guide.md)
