"""Tests for the crt.sh passive-DNS / certificate-transparency enricher
(v0.8.0 step 3).

HTTP lookups are mocked with respx (same pattern as test_epss.py); settings
are switched via env vars plus an explicit get_settings cache clear.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy import select

from scry.config import get_settings

CRT_URL = "https://crt.sh/"
CRT_ANY = re.compile(r"https://crt\.sh/")

DOMAIN_A = "example.com"
DOMAIN_B = "evil-c2.net"


def _entries(*name_values: str) -> list[dict]:
    return [{"name_value": nv, "issuer_name": "CA"} for nv in name_values]


@pytest.fixture
def pdns_settings(monkeypatch):
    """Fast rate limit + generous cap; no keyed-provider keys (the .env file
    may define some — an explicit empty env var overrides it)."""
    for var in (
        "CTI_VIRUSTOTAL_API_KEY",
        "CTI_OTX_API_KEY",
        "CTI_ABUSEIPDB_API_KEY",
        "CTI_GREYNOISE_API_KEY",
    ):
        monkeypatch.setenv(var, "")
    monkeypatch.setenv("CTI_PASSIVE_DNS_MAX_PER_RUN", "50")
    monkeypatch.setenv("CTI_PASSIVE_DNS_REFRESH_DAYS", "14")
    get_settings.cache_clear()
    yield True
    get_settings.cache_clear()


def _seed_observable(session, type_: str, value: str, **kwargs):
    from scry.models import Observable

    row = Observable(type=type_, value=value, normalized_value=value.lower(), **kwargs)
    session.add(row)
    session.commit()
    return row


def _mock_crtsh(handler=None):
    """respx route for crt.sh; default handler returns two SANs per domain."""
    if handler is None:

        def handler(request):
            domain = request.url.params["q"].lstrip("%.")
            return httpx.Response(200, json=_entries(f"www.{domain}", f"mail.{domain}\nstatic.{domain}"))

    return respx.route(method="GET", url=CRT_ANY).mock(side_effect=handler)


class TestParseSubdomains:
    def test_multi_san_entries_are_split(self):
        from scry.enrichment.passive_dns import parse_subdomains

        names = parse_subdomains(_entries("a.example.com\nb.example.com", "c.example.com"), DOMAIN_A)
        assert names == ["a.example.com", "b.example.com", "c.example.com"]

    def test_dedupes_repeated_names(self):
        from scry.enrichment.passive_dns import parse_subdomains

        names = parse_subdomains(
            _entries("www.example.com", "www.example.com\nmail.example.com", "WWW.EXAMPLE.COM"), DOMAIN_A
        )
        assert names == ["mail.example.com", "www.example.com"]

    def test_lowercases_names(self):
        from scry.enrichment.passive_dns import parse_subdomains

        names = parse_subdomains(_entries("WWW.Example.COM"), DOMAIN_A)
        assert names == ["www.example.com"]

    def test_filters_bare_queried_domain(self):
        from scry.enrichment.passive_dns import parse_subdomains

        names = parse_subdomains(_entries("example.com", "www.example.com\nexample.com"), DOMAIN_A)
        assert names == ["www.example.com"]

    def test_strips_wildcard_prefix(self):
        from scry.enrichment.passive_dns import parse_subdomains

        names = parse_subdomains(_entries("*.example.com", "api.example.com"), DOMAIN_A)
        assert names == ["api.example.com"]

    def test_drops_unrelated_names_sharing_a_certificate(self):
        from scry.enrichment.passive_dns import parse_subdomains

        names = parse_subdomains(_entries("www.example.com\nother.org\nsub.other.org"), DOMAIN_A)
        assert names == ["www.example.com"]

    def test_empty_result_yields_no_names(self):
        from scry.enrichment.passive_dns import parse_subdomains

        assert parse_subdomains([], DOMAIN_A) == []

    def test_non_array_response_is_enrichment_error(self):
        from scry.enrichment.base import EnrichmentError
        from scry.enrichment.passive_dns import parse_subdomains

        with pytest.raises(EnrichmentError, match="not a JSON array"):
            parse_subdomains({"unexpected": "object"}, DOMAIN_A)


class TestPassiveDnsEnricher:
    @respx.mock
    def test_enrich_stores_count_samples_and_timestamp(self, pdns_settings):
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        route = _mock_crtsh()

        out = PassiveDnsEnricher(min_interval=0).enrich(DOMAIN_A)

        assert route.called
        assert out.fields["_passive_dns_status"] == "ok"
        assert out.fields["passive_dns_count"] == 3
        assert out.fields["passive_dns_samples"] == [
            f"mail.{DOMAIN_A}",
            f"static.{DOMAIN_A}",
            f"www.{DOMAIN_A}",
        ]
        assert out.fields["passive_dns_enriched_at"]

    @respx.mock
    def test_wildcard_query_param(self, pdns_settings):
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        route = _mock_crtsh()

        PassiveDnsEnricher(min_interval=0).lookup(DOMAIN_A)

        assert route.calls[0].request.url.params["q"] == f"%.{DOMAIN_A}"
        assert route.calls[0].request.url.params["output"] == "json"

    @respx.mock
    def test_samples_capped_at_25(self, pdns_settings):
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        many = "\n".join(f"host{i:02d}.{DOMAIN_A}" for i in range(30))
        _mock_crtsh(lambda request: httpx.Response(200, json=_entries(many)))

        out = PassiveDnsEnricher(min_interval=0).enrich(DOMAIN_A)

        assert out.fields["passive_dns_count"] == 30
        assert len(out.fields["passive_dns_samples"]) == 25

    @respx.mock
    def test_empty_result_is_ok_with_count_zero(self, pdns_settings):
        """Domain absent from CT logs: enriched-but-empty, must not error."""
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        _mock_crtsh(lambda request: httpx.Response(200, json=[]))

        out = PassiveDnsEnricher(min_interval=0).enrich(DOMAIN_A)

        assert out.fields["_passive_dns_status"] == "ok"
        assert out.fields["passive_dns_count"] == 0
        assert out.fields["passive_dns_samples"] == []

    @respx.mock
    def test_timeout_is_skip_not_error(self, pdns_settings):
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        _mock_crtsh(lambda request: httpx.Response(504, json=[])).mock(
            side_effect=httpx.ReadTimeout("crt.sh too slow")
        )

        out = PassiveDnsEnricher(min_interval=0).enrich(DOMAIN_A)

        assert out.fields["_passive_dns_status"] == "skipped"
        assert "timeout" in out.fields["passive_dns_note"]

    @respx.mock
    def test_http_error_raises_enrichment_error(self, pdns_settings):
        from scry.enrichment.base import EnrichmentError
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        _mock_crtsh(lambda request: httpx.Response(500, text="boom"))

        with pytest.raises(EnrichmentError, match=r"crt\.sh HTTP 500"):
            PassiveDnsEnricher(min_interval=0).lookup(DOMAIN_A)

    @respx.mock
    def test_transport_error_raises_enrichment_error(self, pdns_settings):
        from scry.enrichment.base import EnrichmentError
        from scry.enrichment.passive_dns import PassiveDnsEnricher

        _mock_crtsh(lambda request: httpx.Response(200, json=[])).mock(
            side_effect=httpx.ConnectError("refused")
        )

        with pytest.raises(EnrichmentError):
            PassiveDnsEnricher(min_interval=0).lookup(DOMAIN_A)


class TestEngineIntegration:
    @respx.mock
    def test_enriches_domains_and_counts(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        domain = _seed_observable(session, "domain", DOMAIN_A)
        ip = _seed_observable(session, "ipv4", "203.0.113.10")  # not a domain: never selected
        route = _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        assert route.call_count == 1  # one request per domain; IP untouched
        assert result["passive_dns_enriched"] == 1
        assert result["passive_dns_skipped"] == 0
        assert result["errors"] == 0
        assert result["providers"] == ["passive_dns"]

        session.expire_all()
        enrichment = domain.enrichment or {}
        assert enrichment["passive_dns_count"] == 3
        assert len(enrichment["passive_dns_samples"]) == 3
        assert enrichment["passive_dns_checked_at"]
        assert enrichment["passive_dns_enriched_at"]
        assert not (ip.enrichment or {}).get("passive_dns_checked_at")

    @respx.mock
    def test_empty_result_sentinel_not_requeried(self, session, pdns_settings):
        """Domain absent from CT logs: count-0 sentinel stored, no re-query
        until the TTL expires."""
        from scry.enrichment.engine import EnrichmentEngine
        from scry.models import Observable

        _seed_observable(session, "domain", DOMAIN_A)
        _mock_crtsh(lambda request: httpx.Response(200, json=[]))

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])
        assert result["passive_dns_enriched"] == 1

        # Second run: sentinel is fresh → no candidates, no HTTP.
        before = len(respx.calls)
        result2 = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])
        assert result2["passive_dns_enriched"] == 0
        assert result2["passive_dns_skipped"] == 0
        assert len(respx.calls) == before

        row = session.scalar(select(Observable).where(Observable.normalized_value == DOMAIN_A))
        assert row.enrichment["passive_dns_count"] == 0
        assert row.enrichment["passive_dns_samples"] == []

    @respx.mock
    def test_timeout_counts_as_skipped_no_marker(self, session, pdns_settings):
        """A crt.sh timeout skips the domain WITHOUT writing a marker, so it
        is retried on the next run; it is not counted as an error."""
        from scry.enrichment.engine import EnrichmentEngine

        _seed_observable(session, "domain", DOMAIN_A)
        _mock_crtsh(lambda request: httpx.Response(200, json=[])).mock(
            side_effect=httpx.ReadTimeout("crt.sh too slow")
        )

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        assert result["passive_dns_enriched"] == 0
        assert result["passive_dns_skipped"] == 1
        assert result["errors"] == 0

    @respx.mock
    def test_http_error_counts_as_error_not_crash(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_observable(session, "domain", DOMAIN_A)
        _mock_crtsh(lambda request: httpx.Response(503, text="down"))

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        assert result["errors"] == 1
        assert result["passive_dns_enriched"] == 0

    @respx.mock
    def test_fresh_marker_skipped_until_ttl(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        now = datetime.now(UTC)
        fresh = _seed_observable(session, "domain", DOMAIN_A)
        fresh.enrichment = {"passive_dns_checked_at": (now - timedelta(days=2)).isoformat()}
        stale = _seed_observable(session, "domain", DOMAIN_B)
        stale.enrichment = {"passive_dns_checked_at": (now - timedelta(days=30)).isoformat()}
        session.commit()

        route = _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        # Only the stale domain is re-queried; fresh one gets no request.
        assert route.call_count == 1
        assert result["passive_dns_enriched"] == 1
        requested_domain = route.calls[0].request.url.params["q"].lstrip("%.")
        assert requested_domain == DOMAIN_B
        session.expire_all()
        assert "passive_dns_count" not in (fresh.enrichment or {})

    @respx.mock
    def test_oldest_first_and_per_run_cap(self, session, pdns_settings, monkeypatch):
        from scry.enrichment.engine import EnrichmentEngine

        monkeypatch.setenv("CTI_PASSIVE_DNS_MAX_PER_RUN", "2")
        get_settings.cache_clear()

        now = datetime.now(UTC)
        # Seed 3 domains: never-checked + two stale with different ages.
        _seed_observable(session, "domain", "a-first.com")
        _seed_observable(
            session,
            "domain",
            "b-second.com",
            enrichment={"passive_dns_checked_at": (now - timedelta(days=40)).isoformat()},
        )
        _seed_observable(
            session,
            "domain",
            "c-third.com",
            enrichment={"passive_dns_checked_at": (now - timedelta(days=20)).isoformat()},
        )

        route = _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        assert route.call_count == 2  # capped at 2 per run
        assert result["passive_dns_enriched"] == 2
        requested = [c.request.url.params["q"].lstrip("%.") for c in route.calls]
        # Never-checked first, then oldest stale (40d before 20d).
        assert requested == ["a-first.com", "b-second.com"]

    @respx.mock
    def test_domain_only_invalid_values_ignored(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_observable(session, "domain", "not a domain")  # fails sanity check
        _seed_observable(session, "domain", DOMAIN_A)
        route = _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        assert route.call_count == 1
        assert result["passive_dns_enriched"] == 1

    @respx.mock
    def test_runs_without_any_provider_keys(self, session, pdns_settings):
        """Keyless passive_dns runs even when every keyed provider is
        unavailable (independent of per-user/system keys, like EPSS)."""
        from scry.enrichment.engine import EnrichmentEngine

        _seed_observable(session, "domain", DOMAIN_A)
        _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])

        assert result["passive_dns_enriched"] == 1
        assert result["providers"] == ["passive_dns"]
        assert "epss_enriched" not in result  # filter excludes the EPSS phase

    @respx.mock
    def test_default_run_includes_passive_dns_alongside_epss(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_observable(session, "domain", DOMAIN_A)
        _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch()

        assert result["passive_dns_enriched"] == 1
        assert "passive_dns" in result["providers"]
        assert "epss" in result["providers"]

    @respx.mock
    def test_passive_dns_excluded_when_filter_names_other_providers(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_observable(session, "domain", DOMAIN_A)

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["epss"])

        assert "passive_dns_enriched" not in result
        assert len(respx.calls) == 0

    def test_unknown_provider_filter_still_rejected(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        with pytest.raises(ValueError, match="Unknown enrichment provider"):
            EnrichmentEngine(session).run_external_enrichment_batch(providers=["nope"])

    @respx.mock
    def test_force_ignores_fresh_sentinels(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        now = datetime.now(UTC)
        _seed_observable(
            session,
            "domain",
            DOMAIN_A,
            enrichment={"passive_dns_checked_at": (now - timedelta(days=1)).isoformat()},
        )
        _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(
            providers=["passive_dns"], force=True
        )

        assert result["passive_dns_enriched"] == 1

    @respx.mock
    def test_unenriched_only_mode_ignores_stale_rows(self, session, pdns_settings):
        from scry.enrichment.engine import EnrichmentEngine

        now = datetime.now(UTC)
        stale = _seed_observable(
            session,
            "domain",
            DOMAIN_B,
            enrichment={"passive_dns_checked_at": (now - timedelta(days=30)).isoformat()},
        )
        _seed_observable(session, "domain", DOMAIN_A)  # never checked: the only candidate
        route = _mock_crtsh()

        result = EnrichmentEngine(session).run_external_enrichment_batch(
            providers=["passive_dns"], include_stale=False
        )

        assert result["passive_dns_enriched"] == 1
        assert route.call_count == 1
        assert route.calls[0].request.url.params["q"] == f"%.{DOMAIN_A}"
        session.expire_all()
        assert "passive_dns_count" not in (stale.enrichment or {})


class TestUiBlock:
    @respx.mock
    def test_detail_page_renders_certificate_transparency_block(self, session, pdns_settings):
        """The observable detail page shows the CT block once enriched."""
        from fastapi.testclient import TestClient

        from scry.enrichment.engine import EnrichmentEngine
        from scry.main import app

        _seed_observable(session, "domain", DOMAIN_A)
        _mock_crtsh()

        EnrichmentEngine(session).run_external_enrichment_batch(providers=["passive_dns"])
        session.expire_all()

        client = TestClient(app)
        r = client.get("/ui/observables/1")
        assert r.status_code == 200
        assert "Certificate transparency" in r.text
        assert f"mail.{DOMAIN_A}" in r.text
        assert "Subdomains seen" in r.text

    def test_detail_page_omits_block_before_enrichment(self, session, pdns_settings):
        from fastapi.testclient import TestClient

        from scry.main import app

        _seed_observable(session, "domain", DOMAIN_A)

        client = TestClient(app)
        r = client.get("/ui/observables/1")
        assert r.status_code == 200
        assert "Certificate transparency" not in r.text
