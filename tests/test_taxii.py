"""Tests for the read-only TAXII 2.1 server (v0.4.0 step 7)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from scry.config import get_settings
from scry.main import app

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


@pytest.fixture
def seeded(session, seed_source):
    from scry.models import Article, Entity, Observable

    session.add(Entity(type="threat_actor", canonical_name="Lazarus Group"))
    session.add(Observable(type="ipv4", value="1.2.3.4", normalized_value="1.2.3.4"))
    session.add(Article(source_id=seed_source.id, title="Analysis", url="https://example.com/a"))
    session.commit()
    return True


@pytest.fixture
def api_key(monkeypatch):
    """Configure a static API key and refresh the cached settings."""
    monkeypatch.setenv("CTI_API_KEY", "test-key")
    get_settings.cache_clear()
    return "test-key"


class TestDiscovery:
    def test_server_discovery(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith(TAXII_MEDIA_TYPE)
        body = r.json()
        assert body["title"] == "scry"
        assert body["default"] in body["api_roots"]
        assert body["api_roots"] == ["http://testserver/taxii2/api-root"]

    def test_server_discovery_without_trailing_slash_redirects(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2", follow_redirects=True)
        assert r.status_code == 200
        assert r.json()["title"] == "scry"

    def test_api_root_discovery(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/api-root/")
        assert r.status_code == 200
        body = r.json()
        assert body["versions"] == [TAXII_MEDIA_TYPE]
        assert body["max_content_length"] > 0

    def test_unknown_api_root_404_taxii_error(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/bogus/")
        assert r.status_code == 404
        assert r.headers["content-type"].startswith(TAXII_MEDIA_TYPE)
        assert "description" in r.json()

    def test_unknown_api_root_collections_404(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/bogus/collections/")
        assert r.status_code == 404
        assert "description" in r.json()


class TestCollections:
    def test_collections_list(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/api-root/collections/")
        assert r.status_code == 200
        collections = {c["id"]: c for c in r.json()["collections"]}
        assert set(collections) == {"intel", "articles"}
        for c in collections.values():
            assert c["can_read"] is True
            assert c["can_write"] is False
            assert c["media_types"] == ["application/stix+json;version=2.1"]


class TestObjects:
    def test_intel_objects_envelope(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/api-root/collections/intel/objects/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/stix+json")
        body = r.json()
        assert body["more"] is False
        assert body["next"] is None
        types = {o["type"] for o in body["objects"]}
        assert "threat-actor" in types
        assert "indicator" in types

    def test_articles_objects_envelope(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/api-root/collections/articles/objects/")
        assert r.status_code == 200
        body = r.json()
        assert {o["type"] for o in body["objects"]} == {"report", "marking-definition"}

    def test_unknown_collection_404_taxii_error(self, seeded):
        with TestClient(app) as client:
            r = client.get("/taxii2/api-root/collections/nope/objects/")
        assert r.status_code == 404
        assert r.headers["content-type"].startswith(TAXII_MEDIA_TYPE)
        assert "description" in r.json()

    def test_pagination_walks_full_manifest(self, seeded):
        with TestClient(app) as client:
            seen: list[str] = []
            next_token = None
            for _ in range(10):
                params = {"limit": 2}
                if next_token:
                    params["next"] = next_token
                r = client.get("/taxii2/api-root/collections/intel/objects/", params=params)
                assert r.status_code == 200
                body = r.json()
                seen.extend(o["id"] for o in body["objects"])
                if not body["more"]:
                    break
                next_token = body["next"]
            else:
                pytest.fail("pagination did not terminate")
        # Full deterministic manifest walked exactly once, no duplicates.
        assert len(seen) == len(set(seen))
        assert len(seen) >= 3


class TestAuth:
    def test_taxii_requires_key_when_configured(self, seeded, api_key):
        """No discovery exemption: TAXII follows the same auth as the API."""
        with TestClient(app) as client:
            for path in (
                "/taxii2/",
                "/taxii2/api-root/",
                "/taxii2/api-root/collections/",
                "/taxii2/api-root/collections/intel/objects/",
            ):
                assert client.get(path).status_code == 401, path

    def test_taxii_accepts_key(self, seeded, api_key):
        headers = {"X-API-Key": api_key}
        with TestClient(app) as client:
            assert client.get("/taxii2/", headers=headers).status_code == 200
            assert client.get("/taxii2/api-root/", headers=headers).status_code == 200
            assert client.get("/taxii2/api-root/collections/", headers=headers).status_code == 200
            assert (
                client.get("/taxii2/api-root/collections/intel/objects/", headers=headers).status_code == 200
            )

    def test_taxii_open_without_key(self, seeded):
        with TestClient(app) as client:
            assert client.get("/taxii2/").status_code == 200
