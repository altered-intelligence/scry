"""Tests for external IOC enrichment providers (step 6).

HTTP lookups are mocked with respx (same pattern as test_alert_channels.py);
settings are switched via env vars plus an explicit get_settings cache
clear. Disk caches are redirected to a tmp dir per test so nothing leaks
between tests or into the repo's .cti_cache.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from scry.config import get_settings

ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
GREYNOISE_COMMUNITY = "https://api.greynoise.io/v3/community/{}"
VT_IP = "https://www.virustotal.com/api/v3/ip_addresses/{}"
OTX_IP = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"

TEST_IP = "198.51.100.23"

ABUSEIPDB_PAYLOAD = {
    "data": {
        "ipAddress": TEST_IP,
        "abuseConfidenceScore": 85,
        "countryCode": "RU",
        "isp": "Example Telecom Ltd",
        "domain": "example-telecom.ru",
        "totalReports": 42,
        "lastReportedAt": "2024-05-01T12:00:00+00:00",
        "numDistinctUsers": 17,
        "usageType": "Hosting",
    }
}

GN_MALICIOUS = {
    "ip": TEST_IP,
    "noise": True,
    "riot": False,
    "classification": "malicious",
    "name": "shady scanner",
    "last_seen": "2024-05-01",
    "link": "https://viz.greynoise.io/ip/" + TEST_IP,
    "message": "Success",
}

GN_RIOT = {
    "ip": TEST_IP,
    "noise": False,
    "riot": True,
    "classification": "benign",
    "name": "Example CDN",
    "last_seen": "2024-05-01",
    "link": "https://viz.greynoise.io/rip/" + TEST_IP,
    "message": "Success",
}

VT_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 12,
                "suspicious": 1,
                "harmless": 50,
                "undetected": 10,
            },
            "reputation": -10,
            "country": "RU",
            "asn": 9000,
            "as_owner": "Example AS",
        }
    }
}

OTX_PAYLOAD = {
    "pulse_info": {"count": 3, "pulses": [{"name": "p1", "tags": ["scanner"], "tlp": "white"}]},
    "reputation": 0,
    "country_name": "Russia",
}


@pytest.fixture(autouse=True)
def _tmp_caches(monkeypatch, tmp_path):
    """Keep provider disk caches out of the repo and out of other tests."""
    import scry.enrichment.abuseipdb as aipdb
    import scry.enrichment.greynoise as gn
    import scry.enrichment.otx as otx
    import scry.enrichment.virustotal as vt

    for mod, name in [(aipdb, "abuseipdb"), (gn, "greynoise"), (otx, "otx"), (vt, "vt")]:
        monkeypatch.setattr(mod, "CACHE_DIR", tmp_path / name)


@pytest.fixture
def all_keys(monkeypatch):
    monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setenv("CTI_OTX_API_KEY", "otx-key")
    monkeypatch.setenv("CTI_ABUSEIPDB_API_KEY", "aipdb-key")
    monkeypatch.setenv("CTI_GREYNOISE_API_KEY", "gn-key")
    monkeypatch.setenv("CTI_VT_RATE_PER_MIN", "1000")
    monkeypatch.setenv("CTI_VT_DAILY_QUOTA", "1000")
    get_settings.cache_clear()
    return True


def _seed_ip(session, value: str = TEST_IP, **kwargs):
    from scry.models import Observable

    ob = Observable(type="ipv4", value=value, normalized_value=value, **kwargs)
    session.add(ob)
    session.commit()
    return ob


class TestAbuseIPDB:
    @respx.mock
    def test_result_mapping_and_tags(self, all_keys):
        from scry.enrichment.abuseipdb import AbuseIPDBEnricher

        route = respx.get(ABUSEIPDB_CHECK).mock(return_value=httpx.Response(200, json=ABUSEIPDB_PAYLOAD))

        out = AbuseIPDBEnricher().enrich(TEST_IP, context={"observable_type": "ipv4"})

        assert route.called
        assert out.fields["_abuseipdb_status"] == "ok"
        aipdb = out.fields["abuseipdb"]
        assert aipdb["abuse_confidence_score"] == 85
        assert aipdb["country_code"] == "RU"
        assert aipdb["isp"] == "Example Telecom Ltd"
        assert aipdb["total_reports"] == 42
        assert aipdb["last_reported_at"] == "2024-05-01T12:00:00+00:00"
        # score >= 80 → malicious; has reports → reported
        assert "abuseipdb:malicious" in out.tags
        assert "abuseipdb:reported" in out.tags
        assert "abuseipdb:suspicious" not in out.tags

    @respx.mock
    def test_suspicious_band(self, all_keys):
        from scry.enrichment.abuseipdb import AbuseIPDBEnricher

        payload = {**ABUSEIPDB_PAYLOAD, "data": {**ABUSEIPDB_PAYLOAD["data"], "abuseConfidenceScore": 60}}
        respx.get(ABUSEIPDB_CHECK).mock(return_value=httpx.Response(200, json=payload))

        out = AbuseIPDBEnricher().enrich(TEST_IP)
        assert "abuseipdb:suspicious" in out.tags
        assert "abuseipdb:malicious" not in out.tags

    @respx.mock
    def test_no_key_skips_gracefully(self, monkeypatch):
        monkeypatch.delenv("CTI_ABUSEIPDB_API_KEY", raising=False)
        get_settings.cache_clear()
        from scry.enrichment.abuseipdb import AbuseIPDBEnricher

        out = AbuseIPDBEnricher().enrich(TEST_IP)
        assert out.fields["_abuseipdb_status"] == "error"
        assert len(respx.calls) == 0


class TestGreyNoise:
    @respx.mock
    def test_malicious_mapping(self, all_keys):
        from scry.enrichment.greynoise import GreyNoiseEnricher

        route = respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )

        out = GreyNoiseEnricher().enrich(TEST_IP, context={"observable_type": "ipv4"})

        assert route.called
        assert out.fields["_greynoise_status"] == "ok"
        gn = out.fields["greynoise"]
        assert gn["classification"] == "malicious"
        assert gn["noise"] is True
        assert gn["riot"] is False
        assert gn["name"] == "shady scanner"
        assert "greynoise:malicious" in out.tags
        assert "greynoise:noise" in out.tags

    @respx.mock
    def test_riot_benign_mapping(self, all_keys):
        from scry.enrichment.greynoise import GreyNoiseEnricher

        respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(return_value=httpx.Response(200, json=GN_RIOT))

        out = GreyNoiseEnricher().enrich(TEST_IP)
        assert "greynoise:benign" in out.tags
        assert "greynoise:riot" in out.tags
        assert "greynoise:noise" not in out.tags

    @respx.mock
    def test_not_observed_cached_as_negative(self, all_keys):
        from scry.enrichment.greynoise import GreyNoiseEnricher

        respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
            return_value=httpx.Response(404, json={"message": "IP not observed"})
        )

        enricher = GreyNoiseEnricher()
        out = enricher.enrich(TEST_IP)
        assert out.fields["greynoise"] == {"not_found": True}
        assert out.tags == []

    @respx.mock
    def test_no_key_skips_gracefully(self, monkeypatch):
        monkeypatch.delenv("CTI_GREYNOISE_API_KEY", raising=False)
        get_settings.cache_clear()
        from scry.enrichment.greynoise import GreyNoiseEnricher

        out = GreyNoiseEnricher().enrich(TEST_IP)
        assert out.fields["_greynoise_status"] == "error"
        assert len(respx.calls) == 0


class TestBatchRun:
    @respx.mock
    def test_all_providers_run_when_keyed(self, all_keys, session):
        _seed_ip(session)
        respx.get(ABUSEIPDB_CHECK).mock(return_value=httpx.Response(200, json=ABUSEIPDB_PAYLOAD))
        respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))
        respx.get(OTX_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=OTX_PAYLOAD))

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run")
        assert r.status_code == 200
        body = r.json()
        assert body["vt_enriched"] == 1
        assert body["otx_enriched"] == 1
        assert body["abuseipdb_enriched"] == 1
        assert body["greynoise_enriched"] == 1
        assert body["errors"] == 0
        assert body["skipped"] == {}

        # Tags merged onto the observable by the engine.
        from scry.models import Observable

        ob = session.get(Observable, 1)
        assert "abuseipdb:malicious" in (ob.tags or [])
        assert "greynoise:malicious" in (ob.tags or [])
        assert "virustotal_checked_at" in ob.enrichment
        assert "greynoise_checked_at" in ob.enrichment

    @respx.mock
    def test_no_key_providers_skipped_gracefully(self, session, monkeypatch):
        for var in [
            "CTI_VIRUSTOTAL_API_KEY",
            "CTI_OTX_API_KEY",
            "CTI_ABUSEIPDB_API_KEY",
            "CTI_GREYNOISE_API_KEY",
        ]:
            # empty env var overrides any .env fallback value
            monkeypatch.setenv(var, "")
        get_settings.cache_clear()
        _seed_ip(session)

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run")
        assert r.status_code == 200
        body = r.json()
        assert body["total_candidates"] == 0  # nothing runnable → nothing selected
        assert body["skipped"] == {
            "virustotal": "no api key",
            "otx": "no api key",
            "abuseipdb": "no api key",
            "greynoise": "no api key",
        }
        assert len(respx.calls) == 0

    @respx.mock
    def test_providers_filter_limits_run(self, all_keys, session):
        _seed_ip(session)
        respx.get(ABUSEIPDB_CHECK).mock(return_value=httpx.Response(200, json=ABUSEIPDB_PAYLOAD))
        respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run", params=[("providers", "abuseipdb")])
        assert r.status_code == 200
        body = r.json()
        assert body["abuseipdb_enriched"] == 1
        assert "vt_enriched" not in body  # not selected → no count key
        assert body["providers"] == ["abuseipdb"]
        assert not vt_route.called
        assert len(respx.calls) == 1  # only AbuseIPDB hit the network

    def test_unknown_provider_rejected(self, all_keys, session):
        _seed_ip(session)
        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run", params=[("providers", "nonsense")])
        assert r.status_code == 400
        assert "Unknown enrichment provider" in r.json()["detail"]

    @respx.mock
    def test_already_checked_observable_skipped(self, all_keys, session):
        # v0.6.0 step 3 — the batch is staleness-aware now: a *fresh* marker
        # (within the refresh TTL) is skipped as fresh_skipped without network
        # calls. (2024-01-01 markers would be STALE now and get re-enriched.)
        from datetime import UTC, datetime

        fresh = datetime.now(UTC).isoformat()
        _seed_ip(
            session,
            enrichment={
                "virustotal_checked_at": fresh,
                "otx_checked_at": fresh,
            },
        )
        respx.get(ABUSEIPDB_CHECK).mock(return_value=httpx.Response(200, json=ABUSEIPDB_PAYLOAD))
        respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        vt_route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))
        otx_route = respx.get(OTX_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=OTX_PAYLOAD))

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run")
        body = r.json()
        assert body["vt_enriched"] == 0
        assert body["otx_enriched"] == 0
        assert body["fresh_skipped"] == {"virustotal": 1, "otx": 1}
        assert not vt_route.called
        assert not otx_route.called


class TestRateLimiting:
    def test_daily_quota_blocks_excess_calls(self):
        from scry.enrichment.ratelimit import DailyQuota

        quota = DailyQuota(2)
        assert quota.consume() is True
        assert quota.consume() is True
        assert quota.consume() is False
        assert quota.remaining == 0

    def test_daily_quota_resets_next_day(self, monkeypatch):
        from datetime import UTC, datetime, timedelta

        from scry.enrichment import ratelimit
        from scry.enrichment.ratelimit import DailyQuota

        quota = DailyQuota(1)
        assert quota.consume() is True
        assert quota.consume() is False

        tomorrow = datetime.now(UTC) + timedelta(days=1)

        class _TomorrowDateTime:
            @staticmethod
            def now(tz=None):
                return tomorrow

        monkeypatch.setattr(ratelimit, "datetime", _TomorrowDateTime)
        assert quota.consume() is True

    @respx.mock
    def test_vt_daily_quota_enforced(self, all_keys, monkeypatch):
        monkeypatch.setenv("CTI_VT_DAILY_QUOTA", "1")
        get_settings.cache_clear()
        from scry.enrichment.virustotal import VirusTotalEnricher

        route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        enricher = VirusTotalEnricher()
        first = enricher.lookup(TEST_IP, "ipv4")
        second = enricher.lookup("198.51.100.99", "ipv4")
        assert first.ok and first.cached is False
        assert not second.ok
        assert "daily quota" in (second.error or "")
        assert route.call_count == 1  # second call never reached the network


class TestProviderSettingsEndpoints:
    def test_list_providers(self, all_keys, session):
        from scry.main import app

        with TestClient(app) as client:
            r = client.get("/enrichment/providers")
        assert r.status_code == 200
        ids = [p["id"] for p in r.json()["providers"]]
        assert ids == ["virustotal", "otx", "abuseipdb", "greynoise"]
        vt = r.json()["providers"][0]
        assert vt["key_present"] is True
        assert vt["api_key_source"] == "env"
        assert vt["enabled"] is True

    @respx.mock
    def test_db_key_persists_and_overrides_env(self, monkeypatch, session):
        """Key set via PUT is encrypted in connector_settings and used by the batch."""
        for var in ["CTI_VIRUSTOTAL_API_KEY", "CTI_OTX_API_KEY"]:
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("CTI_VT_RATE_PER_MIN", "1000")
        get_settings.cache_clear()
        _seed_ip(session)
        route = respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))

        from scry.main import app

        with TestClient(app) as client:
            r = client.put(
                "/enrichment/providers",
                json={"provider": "virustotal", "enabled": True, "api_key": "db-vt-key"},
            )
        assert r.status_code == 200
        entry = r.json()
        assert entry["key_present"] is True
        assert entry["api_key_source"] == "db"
        assert entry["api_key_masked"].endswith("key")

        # Raw DB row stores ciphertext, not the plaintext key.
        from scry.models import ConnectorSetting

        row = session.query(ConnectorSetting).filter_by(provider="virustotal").one()
        assert row.api_key_encrypted != "db-vt-key"
        assert "db-vt-key" not in row.api_key_encrypted

        with TestClient(app) as client:
            r = client.post("/enrichment/run")
        assert r.json()["vt_enriched"] == 1
        assert route.called

    @respx.mock
    def test_disabled_provider_skipped_with_reason(self, all_keys, session):
        _seed_ip(session)
        respx.get(ABUSEIPDB_CHECK).mock(return_value=httpx.Response(200, json=ABUSEIPDB_PAYLOAD))
        respx.get(GREYNOISE_COMMUNITY.format(TEST_IP)).mock(
            return_value=httpx.Response(200, json=GN_MALICIOUS)
        )
        respx.get(VT_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=VT_PAYLOAD))
        otx_route = respx.get(OTX_IP.format(TEST_IP)).mock(return_value=httpx.Response(200, json=OTX_PAYLOAD))

        from scry.main import app

        with TestClient(app) as client:
            put = client.put("/enrichment/providers", json={"provider": "otx", "enabled": False})
        assert put.status_code == 200

        with TestClient(app) as client:
            r = client.post("/enrichment/run")
        body = r.json()
        assert body["skipped"]["otx"] == "disabled"
        assert "otx_enriched" not in body
        assert not otx_route.called

    def test_clear_api_key(self, all_keys, session):
        from scry.main import app

        with TestClient(app) as client:
            client.put(
                "/enrichment/providers",
                json={"provider": "greynoise", "enabled": True, "api_key": "gn-db-key"},
            )
            r = client.put(
                "/enrichment/providers",
                json={"provider": "greynoise", "enabled": True, "clear_api_key": True},
            )
        entry = r.json()
        # env fallback applies again after the DB key is cleared
        assert entry["api_key_source"] == "env"
        assert entry["key_present"] is True

    def test_unknown_provider_rejected(self, session):
        from scry.main import app

        with TestClient(app) as client:
            r = client.put("/enrichment/providers", json={"provider": "nope", "enabled": True})
        assert r.status_code == 404


class TestAlertsPagePanel:
    def test_panel_renders_provider_state(self, all_keys):
        from scry.main import app

        with TestClient(app) as client:
            r = client.get("/ui/alerts")
        assert r.status_code == 200
        assert "System keys (background jobs)" in r.text
        assert "VirusTotal" in r.text
        assert "AbuseIPDB" in r.text
        assert "GreyNoise" in r.text
        # all_keys fixture sets every env key → no missing-key badges
        assert '<span class="badge dim">no key</span>' not in r.text

    def test_panel_shows_missing_key(self, monkeypatch):
        for var in ["CTI_VIRUSTOTAL_API_KEY", "CTI_OTX_API_KEY"]:
            monkeypatch.setenv(var, "")  # empty overrides the .env fallback
        get_settings.cache_clear()
        from scry.main import app

        with TestClient(app) as client:
            r = client.get("/ui/alerts")
        assert '<span class="badge dim">no key</span>' in r.text
