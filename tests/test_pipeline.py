from datetime import UTC, datetime

from scry.models import Article, Claim, Observable
from scry.pipeline import CTIPipeline


def _article(session, seed_source, text: str, url: str = "https://example.com/article") -> Article:
    a = Article(
        source_id=seed_source.id,
        title="Threat report",
        url=url,
        ingested_at=datetime.now(UTC),
        published_at=datetime.now(UTC),
        extracted_text=text,
        source_confidence=seed_source.baseline_confidence,
    )
    session.add(a)
    session.commit()
    return a


def test_pipeline_ransomware(session, seed_source, fixture_dir):
    art = _article(session, seed_source, (fixture_dir / "ransomware.txt").read_text())
    CTIPipeline(session).process_article(art)
    obs = list(session.query(Observable).all())
    types = {o.type for o in obs}
    assert {"ipv4", "sha256", "cve"} <= types
    claims = list(session.query(Claim).all())
    assert any(c.claim_type == "ransomware_deployment" for c in claims)


def test_pipeline_microsoft_cve(session, seed_source, fixture_dir):
    art = _article(
        session, seed_source, (fixture_dir / "microsoft_cve.txt").read_text(), url="https://example.com/ms"
    )
    CTIPipeline(session).process_article(art)
    obs = [o for o in session.query(Observable).all() if o.type == "cve"]
    assert any(o.normalized_value == "CVE-2026-12001" for o in obs)
    assert "microsoft" in art.tags
    assert "exploited-in-the-wild" in art.tags


def test_pipeline_adds_article_source_and_entity_tags_to_iocs(session, seed_source):
    art = _article(
        session,
        seed_source,
        "APT28 used Cobalt Strike infrastructure at malicious-update.net for command-and-control.",
        url="https://example.com/context-tags",
    )
    CTIPipeline(session).process_article(art)
    ob = session.query(Observable).filter_by(normalized_value="malicious-update.net").one()
    assert "vendor" in ob.tags
    assert "source:test-vendor-blog" in ob.tags
    assert "source-type:vendor-blog" in ob.tags
    assert "threat-actor:apt28" in ob.tags
    assert "actor:apt28" in ob.tags
    assert "malware-family:cobalt-strike" in ob.tags
    assert "malware:cobalt-strike" in ob.tags


def test_pipeline_benign_routes_to_review(session, seed_source, fixture_dir):
    art = _article(
        session, seed_source, (fixture_dir / "benign_noise.txt").read_text(), url="https://example.com/benign"
    )
    CTIPipeline(session).process_article(art)
    # github.com / microsoft.com should be tagged benign and not block-recommended.
    obs = session.query(Observable).all()
    for o in obs:
        if o.normalized_value in ("github.com", "microsoft.com", "cloudflare.com"):
            assert o.actionability == "monitor"
