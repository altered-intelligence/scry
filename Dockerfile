# syntax=docker/dockerfile:1

# ── Builder: resolve and install the pinned dependency set into a venv ──────
# Compilers live only in this stage; nothing here reaches the final image.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# psycopg[binary] ships wheels (bundling libpq), but keep a toolchain as a
# source-build fallback for platforms without a matching wheel.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Dependencies first (cached layer — only rebuilt when the lock changes)…
COPY pyproject.toml README.md requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock

# …then the app itself, without re-resolving dependencies.
COPY scry ./scry
RUN pip install --no-cache-dir --no-deps .

# ── Runtime: slim, non-root, no toolchain ───────────────────────────────────
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    # The package lives in read-only site-packages, so relocate the
    # auto-generated Fernet key onto the writable data dir.
    CTI_SECRET_FILE=/app/data/.cti_secret

# Runtime deps are self-contained wheels (psycopg[binary] bundles libpq,
# cryptography/lxml/pillow link statically), so no system packages here.
RUN groupadd --gid 1000 scry \
    && useradd --uid 1000 --gid scry --shell /usr/sbin/nologin --no-create-home scry \
    && mkdir -p /app/data \
    && chown -R scry:scry /app

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY config ./config
COPY alembic ./alembic
COPY alembic.ini ./

USER scry
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)" || exit 1

CMD ["uvicorn", "scry.main:app", "--host", "0.0.0.0", "--port", "8000"]
