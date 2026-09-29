FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY scry ./scry
COPY alembic ./alembic
COPY alembic.ini ./alembic.ini
COPY config ./config

RUN pip install --upgrade pip && pip install .

EXPOSE 8000
CMD ["uvicorn", "scry.main:app", "--host", "0.0.0.0", "--port", "8000"]
