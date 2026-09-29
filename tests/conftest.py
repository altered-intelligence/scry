"""Pytest fixtures.

Tests run against an in-memory SQLite database. Each test gets a clean
schema so they can run in parallel safely.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch, tmp_path: Path):
    db_path = tmp_path / "test.sqlite"
    monkeypatch.setenv("CTI_DATABASE_URL", f"sqlite+pysqlite:///{db_path}")
    monkeypatch.setenv("CTI_ENV", "test")
    monkeypatch.setenv("CTI_ENABLE_DARK_WEB", "false")
    monkeypatch.setenv("CTI_ENABLE_FILE_DOWNLOADS", "false")

    # Reset cached singletons
    from scry import config as _config
    from scry import db as _db

    _config.get_settings.cache_clear()
    _db.reset_engine_for_tests()

    from scry.db import get_engine
    from scry.models.base import Base

    Base.metadata.create_all(bind=get_engine())
    yield


@pytest.fixture
def session():
    from scry.db import session_scope

    with session_scope() as s:
        yield s


@pytest.fixture
def fixture_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def seed_source(session):
    from scry.models import Source

    src = Source(
        name="Test Vendor Blog",
        type="vendor_blog",
        url="https://example.com/blog",
        feed="https://example.com/blog/feed",
        enabled=True,
        priority="high",
        baseline_confidence=90,
        collection_policy="safe_public_web",
        independent=True,
        rate_limit_per_minute=10,
        tags=["vendor"],
    )
    session.add(src)
    session.commit()
    return src
