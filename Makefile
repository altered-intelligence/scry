.PHONY: help install init-db ingest test lint format clean compose-up compose-down

help:
	@echo "Targets:"
	@echo "  install      Create .venv and install deps"
	@echo "  init-db      Create schema and load sources.yaml"
	@echo "  ingest       Run ingestion across all enabled sources"
	@echo "  test         Run pytest"
	@echo "  lint         Run ruff + mypy"
	@echo "  format       Run black + ruff --fix"
	@echo "  compose-up   docker compose up postgres + api"
	@echo "  compose-down docker compose down"

install:
	python3 -m venv .venv && .venv/bin/pip install -U pip && .venv/bin/pip install -e ".[dev]"

init-db:
	.venv/bin/scry init-db

ingest:
	.venv/bin/scry ingest-all

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check scry tests && .venv/bin/mypy scry || true

format:
	.venv/bin/black scry tests && .venv/bin/ruff check --fix scry tests

compose-up:
	docker compose up -d postgres && docker compose up api

compose-down:
	docker compose down

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info
