from sqlalchemy import select

from scry.ingestion.source_registry import SourceRegistry
from scry.models import Source


def test_sync_from_yaml_creates_sources(session):
    res = SourceRegistry(session).sync_from_yaml()
    assert res["added"] > 0
    names = [s.name for s in session.scalars(select(Source))]
    assert "CISA KEV" in names
    assert any("Microsoft" in n or "Crowdstrike" in n or "CrowdStrike" in n for n in names)


def test_disabled_sources_remain_disabled(session):
    SourceRegistry(session).sync_from_yaml()
    onion = session.scalar(select(Source).where(Source.type == "onion"))
    assert onion is not None and not onion.enabled
