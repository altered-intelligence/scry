"""Tests for spec-valid STIX 2.1 export (v0.4.0 step 7)."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from scry.exports.stix21 import build_articles_bundle, build_intel_bundle
from scry.main import app


@pytest.fixture
def seeded(session, seed_source):
    from scry.models import (
        Article,
        Entity,
        EntityMention,
        Observable,
        ObservableMention,
        Relationship,
    )

    actor = Entity(
        type="threat_actor",
        canonical_name="Lazarus Group",
        aliases=["Diamond Sleet"],
        description="State-sponsored actor.",
        tags=["apt"],
        confidence=80,
    )
    malware = Entity(
        type="malware_family",
        canonical_name="FakeMal",
        aliases=[],
        tags=["ransomware"],
    )
    campaign = Entity(type="campaign", canonical_name="Operation FakeNews")
    org = Entity(type="organization", canonical_name="Contoso Ltd")
    session.add_all([actor, malware, campaign, org])
    session.flush()

    obs_ipv4 = Observable(
        type="ipv4", value="1.2.3.4", normalized_value="1.2.3.4", risk_score=88.0, tags=["c2"]
    )
    obs_domain = Observable(type="domain", value="evil.example.com", normalized_value="evil.example.com")
    obs_url = Observable(
        type="url", value="https://evil.example.com/a", normalized_value="https://evil.example.com/a"
    )
    obs_sha = Observable(
        type="sha256",
        value="a" * 64,
        normalized_value="a" * 64,
        first_seen=None,
    )
    session.add_all([obs_ipv4, obs_domain, obs_url, obs_sha])
    session.flush()

    article = Article(
        source_id=seed_source.id,
        title="FakeMal campaign analysis",
        url="https://example.com/blog/fakemal",
        extracted_text="Lazarus Group uses FakeMal.",
        tags=["analysis"],
    )
    session.add(article)
    session.flush()
    session.add(EntityMention(entity_id=actor.id, article_id=article.id))
    session.add(EntityMention(entity_id=malware.id, article_id=article.id))
    session.add(ObservableMention(observable_id=obs_ipv4.id, article_id=article.id))

    session.add_all(
        [
            Relationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="malware_family",
                target_id=malware.id,
                relationship_type="uses",
                confidence=70,
                evidence_text="Lazarus Group uses FakeMal.",
            ),
            Relationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="ipv4",
                target_id=obs_ipv4.id,
                relationship_type="communicates_with",
            ),
            # Unmappable endpoint kinds are dropped, not mis-resolved.
            Relationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="unknown_thing",
                target_id=999,
                relationship_type="frobnicates",
            ),
        ]
    )
    session.commit()
    return {
        "actor": actor,
        "malware": malware,
        "campaign": campaign,
        "org": org,
        "obs_ipv4": obs_ipv4,
        "obs_domain": obs_domain,
        "obs_url": obs_url,
        "obs_sha": obs_sha,
        "article": article,
    }


_COMMON_REQUIRED = ("type", "id", "spec_version", "created", "modified")


def _by_type(bundle: dict, obj_type: str) -> list[dict]:
    return [o for o in bundle["objects"] if o["type"] == obj_type]


class TestBundleStructure:
    def test_bundle_envelope(self, session, seeded):
        bundle = build_intel_bundle(session)
        assert bundle["type"] == "bundle"
        assert re.fullmatch(r"bundle--[0-9a-f-]{36}", bundle["id"])
        # STIX 2.1: no spec_version at bundle level.
        assert "spec_version" not in bundle
        assert isinstance(bundle["objects"], list) and bundle["objects"]

    def test_every_object_has_common_required_fields(self, session, seeded):
        bundle = build_intel_bundle(session)
        for obj in bundle["objects"]:
            assert obj["spec_version"] == "2.1"
            assert re.fullmatch(r"[a-z0-9-]+--[0-9a-f-]{36}", obj["id"])
        for obj in bundle["objects"]:
            if obj["type"] in {
                "threat-actor",
                "malware",
                "campaign",
                "intrusion-set",
                "tool",
                "identity",
                "location",
                "vulnerability",
                "indicator",
                "report",
                "relationship",
                "marking-definition",
            }:
                for key in _COMMON_REQUIRED:
                    if obj["type"] == "marking-definition" and key == "modified":
                        continue  # marking-definition has no modified
                    assert key in obj, f"{obj['type']} missing {key}"

    def test_entity_sdo_required_props(self, session, seeded):
        bundle = build_intel_bundle(session)
        actors = _by_type(bundle, "threat-actor")
        assert len(actors) == 1
        assert actors[0]["name"] == "Lazarus Group"
        assert actors[0]["aliases"] == ["Diamond Sleet"]

        malware = _by_type(bundle, "malware")
        assert len(malware) == 1
        assert malware[0]["name"] == "FakeMal"
        assert malware[0]["is_family"] is True

        campaigns = _by_type(bundle, "campaign")
        assert campaigns[0]["name"] == "Operation FakeNews"

        identities = _by_type(bundle, "identity")
        assert len(identities) == 1
        assert identities[0]["identity_class"] == "organization"
        assert identities[0]["name"] == "Contoso Ltd"

    def test_indicator_required_props_and_patterns(self, session, seeded):
        bundle = build_intel_bundle(session)
        indicators = _by_type(bundle, "indicator")
        assert len(indicators) == 4
        for ind in indicators:
            assert ind["pattern_type"] == "stix"
            assert ind["pattern"].startswith("[") and ind["pattern"].endswith("]")
            assert "valid_from" in ind

        patterns = {ind["name"].split(": ", 1)[1]: ind["pattern"] for ind in indicators}
        assert patterns["1.2.3.4"] == "[ipv4-addr:value = '1.2.3.4']"
        assert patterns["evil.example.com"] == "[domain-name:value = 'evil.example.com']"
        assert patterns["https://evil.example.com/a"] == "[url:value = 'https://evil.example.com/a']"
        assert patterns["a" * 64] == f"[file:hashes.'SHA-256' = '{'a' * 64}']"

    def test_sco_objects(self, session, seeded):
        bundle = build_intel_bundle(session)
        ipv4 = _by_type(bundle, "ipv4-addr")
        assert ipv4 and ipv4[0]["value"] == "1.2.3.4"
        assert "created" not in ipv4[0]  # SCOs carry no timestamps
        domains = _by_type(bundle, "domain-name")
        assert domains and domains[0]["value"] == "evil.example.com"
        urls = _by_type(bundle, "url")
        assert urls and urls[0]["value"] == "https://evil.example.com/a"
        files = _by_type(bundle, "file")
        assert files and files[0]["hashes"] == {"SHA-256": "a" * 64}

    def test_relationship_sdrs(self, session, seeded):
        bundle = build_intel_bundle(session)
        rels = _by_type(bundle, "relationship")
        # The third relationship has an unmappable target and is dropped.
        assert len(rels) == 2
        by_type = {r["relationship_type"]: r for r in rels}
        assert set(by_type) == {"uses", "communicates-with"}
        uses = by_type["uses"]
        actor_id = _by_type(bundle, "threat-actor")[0]["id"]
        malware_id = _by_type(bundle, "malware")[0]["id"]
        assert uses["source_ref"] == actor_id
        assert uses["target_ref"] == malware_id
        for r in rels:
            assert r["source_ref"].count("--") == 1
            assert r["target_ref"].count("--") == 1

    def test_marking_definition_present(self, session, seeded):
        bundle = build_intel_bundle(session)
        markings = _by_type(bundle, "marking-definition")
        assert len(markings) == 1
        md = markings[0]
        assert md["definition_type"] == "statement"
        assert "statement" in md["definition"]
        for obj in bundle["objects"]:
            if obj["type"] != "marking-definition":
                assert md["id"] in obj["object_marking_refs"]

    def test_uuid_determinism(self, session, seeded):
        first = build_intel_bundle(session)
        second = build_intel_bundle(session)
        assert first["id"] == second["id"]
        assert [o["id"] for o in first["objects"]] == [o["id"] for o in second["objects"]]

    def test_limit(self, session, seeded):
        bundle = build_intel_bundle(session, limit=1)
        # 1 marking + up to 1 entity (+ its observables/relationships limited too)
        assert len(bundle["objects"]) <= 4


class TestArticlesBundle:
    def test_report_required_props(self, session, seeded):
        bundle = build_articles_bundle(session)
        assert "spec_version" not in bundle
        reports = _by_type(bundle, "report")
        assert len(reports) == 1
        report = reports[0]
        assert report["name"] == "FakeMal campaign analysis"
        assert "published" in report
        assert re.fullmatch(r"report--[0-9a-f-]{36}", report["id"])
        ext = report["external_references"][0]
        assert ext["url"] == "https://example.com/blog/fakemal"

    def test_report_object_refs_point_at_intel_ids(self, session, seeded):
        intel = build_intel_bundle(session)
        articles = build_articles_bundle(session)
        report = _by_type(articles, "report")[0]
        intel_ids = {o["id"] for o in intel["objects"]}
        assert report["object_refs"], "expected object_refs from mentions"
        assert set(report["object_refs"]) <= intel_ids

    def test_articles_limit(self, session, seeded):
        bundle = build_articles_bundle(session, limit=1)
        assert len(_by_type(bundle, "report")) == 1


class TestExportEndpoint:
    def test_export_stix21_default_intel(self, session, seeded):
        with TestClient(app) as client:
            r = client.post("/exports/stix21")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/stix+json")
        bundle = r.json()
        assert bundle["type"] == "bundle"
        assert _by_type(bundle, "threat-actor")

    def test_export_stix21_articles(self, session, seeded):
        with TestClient(app) as client:
            r = client.post("/exports/stix21", json={"collection": "articles", "limit": 5})
        assert r.status_code == 200
        bundle = r.json()
        assert _by_type(bundle, "report")

    def test_export_stix21_invalid_collection(self, session, seeded):
        with TestClient(app) as client:
            r = client.post("/exports/stix21", json={"collection": "nope"})
        assert r.status_code == 422
