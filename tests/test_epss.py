"""Tests for the FIRST.org EPSS enricher + engine integration (v0.8.0 step 2).

HTTP lookups are mocked with respx (same pattern as test_enrichment_providers.py);
settings are switched via env vars plus an explicit get_settings cache clear.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy import select

from scry.config import get_settings

EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_ANY = re.compile(r"https://api\.first\.org/data/v1/epss")

CVE_A = "CVE-2021-44228"
CVE_B = "CVE-2023-4863"
CVE_UNKNOWN = "CVE-1900-0001"


def _payload(ids: dict[str, tuple[str, str]] | list[str]) -> dict:
    """Build an EPSS API response. Dict values are (epss, percentile) strings."""
    if isinstance(ids, dict):
        return {"data": [{"cve": c, "epss": e, "percentile": p} for c, (e, p) in ids.items()]}
    return {"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in ids]}


@pytest.fixture
def epss_settings(monkeypatch):
    """Fast rate limit + generous cap; no keyed-provider keys (the .env file
    may define some — an explicit empty env var overrides it)."""
    for var in (
        "CTI_VIRUSTOTAL_API_KEY",
        "CTI_OTX_API_KEY",
        "CTI_ABUSEIPDB_API_KEY",
        "CTI_GREYNOISE_API_KEY",
    ):
        monkeypatch.setenv(var, "")
    monkeypatch.setenv("CTI_EPSS_MAX_PER_RUN", "100")
    monkeypatch.setenv("CTI_EPSS_REFRESH_DAYS", "7")
    get_settings.cache_clear()
    yield True
    get_settings.cache_clear()


def _seed_cve(session, cve_id: str, **kwargs):
    from scry.models import CVE

    row = CVE(cve_id=cve_id, **kwargs)
    session.add(row)
    session.commit()
    return row


class TestModelAndMigration:
    def test_columns_present_on_fresh_db(self, session):
        from sqlalchemy import inspect

        from scry.db import get_engine

        cols = {c["name"] for c in inspect(get_engine()).get_columns("cves")}
        assert "epss_percentile" in cols
        assert "epss_enriched_at" in cols

    def test_migration_applies_to_legacy_db(self, tmp_path, monkeypatch):
        """A pre-v0.8.0 cves table (no EPSS columns) gains them via ALTER."""
        from sqlalchemy import create_engine, inspect, text

        from scry.migrations import run_migrations

        legacy = create_engine(f"sqlite+pysqlite:///{tmp_path}/legacy.sqlite")
        with legacy.begin() as conn:
            # Minimal stand-ins for every table MIGRATIONS touches, in the
            # pre-v0.8.0 shape (no EPSS columns on cves).
            conn.execute(text("CREATE TABLE cves (id INTEGER PRIMARY KEY, cve_id VARCHAR(32))"))
            conn.execute(text("CREATE TABLE chat_sessions (id INTEGER PRIMARY KEY)"))
            conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY)"))
            conn.execute(text("CREATE TABLE connector_settings (id INTEGER PRIMARY KEY)"))
        monkeypatch.setattr("scry.migrations.get_engine", lambda: legacy)
        run_migrations()
        cols = {c["name"] for c in inspect(legacy).get_columns("cves")}
        assert {"epss_percentile", "epss_enriched_at"} <= cols

    def test_migration_is_idempotent(self, epss_settings):
        from scry.migrations import run_migrations

        run_migrations()
        run_migrations()  # second pass must be a no-op, not an error


class TestEpsEnricher:
    @respx.mock
    def test_parses_single_response(self, epss_settings):
        from scry.enrichment.epss import EpsEnricher

        route = respx.get(EPSS_URL, params={"cve": CVE_A}).mock(
            return_value=httpx.Response(200, json=_payload({CVE_A: ("0.975", "0.999")}))
        )
        out = EpsEnricher(min_interval=0).enrich(CVE_A, context={"cve_id": CVE_A})

        assert route.called
        assert out.fields["_epss_status"] == "ok"
        assert out.fields["epss"]["epss"] == pytest.approx(0.975)
        assert out.fields["epss"]["percentile"] == pytest.approx(0.999)

    @respx.mock
    def test_batch_uses_comma_joined_request(self, epss_settings):
        from scry.enrichment.epss import EpsEnricher

        route = respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json=_payload([CVE_A, CVE_B])))

        result = EpsEnricher(min_interval=0).enrich_batch([CVE_A, CVE_B])

        assert route.called
        requested = route.calls[0].request.url.params["cve"]
        assert set(requested.split(",")) == {CVE_A, CVE_B}
        assert result.ok
        assert result.records[CVE_A].epss == pytest.approx(0.5)
        assert result.records[CVE_B].percentile == pytest.approx(0.9)
        assert result.not_found == []

    @respx.mock
    def test_unknown_cve_is_not_found_not_error(self, epss_settings):
        from scry.enrichment.epss import EpsEnricher

        respx.get(EPSS_ANY).mock(return_value=httpx.Response(200, json={"data": []}))

        result = EpsEnricher(min_interval=0).enrich_batch([CVE_UNKNOWN])

        assert result.ok
        assert result.records == {}
        assert result.not_found == [CVE_UNKNOWN]

        out = EpsEnricher(min_interval=0).enrich(CVE_UNKNOWN)
        assert out.fields["_epss_status"] == "not_found"

    @respx.mock
    def test_http_error_raises_enrichment_error(self, epss_settings):
        from scry.enrichment.base import EnrichmentError
        from scry.enrichment.epss import EpsEnricher

        respx.get(EPSS_ANY).mock(return_value=httpx.Response(500, text="boom"))

        with pytest.raises(EnrichmentError, match="EPSS HTTP 500"):
            EpsEnricher(min_interval=0).enrich_batch([CVE_A])

    @respx.mock
    def test_transport_error_raises_enrichment_error(self, epss_settings):
        from scry.enrichment.base import EnrichmentError
        from scry.enrichment.epss import EpsEnricher

        respx.get(EPSS_ANY).mock(side_effect=httpx.ConnectError("refused"))

        with pytest.raises(EnrichmentError):
            EpsEnricher(min_interval=0).enrich_batch([CVE_A])

    @respx.mock
    def test_batch_size_caps_request(self, epss_settings):
        from scry.enrichment.epss import EpsEnricher

        route = respx.get(EPSS_ANY).mock(
            side_effect=lambda request: httpx.Response(
                200, json=_payload(request.url.params["cve"].split(","))
            )
        )
        ids = [f"CVE-2024-{i:05d}" for i in range(65)]

        result = EpsEnricher(min_interval=0).enrich_batch(ids)

        assert route.call_count == 3  # 30 + 30 + 5
        assert set(result.records) == set(ids)


def _mock_epss_api(known: dict[str, tuple[str, str]] | None = None):
    """respx side effect: score every requested CVE via the known mapping
    (all of them when known is None)."""

    def handler(request):
        data = []
        for c in request.url.params["cve"].split(","):
            if known is None:
                data.append({"cve": c, "epss": "0.5", "percentile": "0.9"})
            elif c in known:
                epss, percentile = known[c]
                data.append({"cve": c, "epss": epss, "percentile": percentile})
        return httpx.Response(200, json={"data": data})

    return respx.route(method="GET", url=EPSS_ANY).mock(side_effect=handler)


class TestEngineIntegration:
    @respx.mock
    def test_selects_due_cves_oldest_first_and_counts(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        now = datetime.now(UTC)
        stale = _seed_cve(session, "CVE-2020-0001", epss_enriched_at=now - timedelta(days=30))
        fresh = _seed_cve(session, "CVE-2020-0002", epss_enriched_at=now - timedelta(days=2))
        never = _seed_cve(session, "CVE-2020-0003")
        known = {
            stale.cve_id: ("0.11", "0.22"),
            never.cve_id: ("0.33", "0.44"),
        }
        requests: list[str] = []

        def handler(request):
            ids = request.url.params["cve"].split(",")
            requests.append(request.url.params["cve"])
            return httpx.Response(
                200,
                json={
                    "data": [
                        {"cve": c, "epss": known[c][0], "percentile": known[c][1]} for c in ids if c in known
                    ]
                },
            )

        respx.route(method="GET", url=EPSS_ANY).mock(side_effect=handler)

        result = EnrichmentEngine(session).run_external_enrichment_batch()

        assert result["epss_enriched"] == 2
        assert result["epss_skipped"] == 0
        assert "epss" in result["providers"]
        # Fresh CVE untouched, no request includes it.
        assert [fresh.cve_id] not in [r.split(",") for r in requests]
        requested = ",".join(requests).split(",")
        assert set(requested) == {stale.cve_id, never.cve_id}
        # Oldest-first: never-checked before stale-dated.
        assert requested[0] == never.cve_id

        session.expire_all()
        assert stale.epss == pytest.approx(0.11)
        assert stale.epss_percentile == pytest.approx(0.22)
        assert never.epss == pytest.approx(0.33)
        assert fresh.epss is None
        assert fresh.epss_enriched_at is not None

    @respx.mock
    def test_respects_per_run_cap(self, session, monkeypatch, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        monkeypatch.setenv("CTI_EPSS_MAX_PER_RUN", "2")
        get_settings.cache_clear()
        ids = [f"CVE-2024-{i:05d}" for i in range(5)]
        for cve_id in ids:
            _seed_cve(session, cve_id)

        _mock_epss_api()

        result = EnrichmentEngine(session).run_external_enrichment_batch()

        assert result["epss_enriched"] == 2

    @respx.mock
    def test_unknown_cve_gets_sentinel_not_requeried(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine
        from scry.models import CVE

        _seed_cve(session, CVE_UNKNOWN)
        _mock_epss_api({})  # EPSS has no score for anything

        result = EnrichmentEngine(session).run_external_enrichment_batch()

        assert result["epss_enriched"] == 0
        assert result["epss_skipped"] == 1
        row = session.scalar(select(CVE).where(CVE.cve_id == CVE_UNKNOWN))
        assert row.epss is None
        assert row.epss_enriched_at is not None  # sentinel: won't re-query forever

        # Second run: sentinel is fresh → no candidates, no HTTP.
        before = len(respx.calls)
        result2 = EnrichmentEngine(session).run_external_enrichment_batch()
        assert result2["epss_enriched"] == 0
        assert result2["epss_skipped"] == 0
        assert len(respx.calls) == before

    @respx.mock
    def test_runs_without_any_provider_keys(self, session, epss_settings):
        """Keyless EPSS runs even when every keyed provider is unavailable."""
        from scry.enrichment.engine import EnrichmentEngine

        _seed_cve(session, CVE_A)
        _mock_epss_api({CVE_A: ("0.5", "0.9")})

        result = EnrichmentEngine(session).run_external_enrichment_batch()

        assert result["epss_enriched"] == 1
        assert "epss" in result["providers"]
        # No keyed provider ran or even appeared in the provider list.
        # v0.8.0 step 3 — the default run now also includes the keyless
        # passive_dns phase (crt.sh), which simply finds no domain candidates.
        assert result["providers"] == ["epss", "passive_dns"]
        assert result["skipped"] != {}  # keyed providers skipped with reasons

    @respx.mock
    def test_epss_only_via_providers_filter(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_cve(session, CVE_A)
        _mock_epss_api({CVE_A: ("0.5", "0.9")})

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["epss"])

        assert result["epss_enriched"] == 1
        assert result["providers"] == ["epss"]
        assert result["total_candidates"] == 0

    @respx.mock
    def test_epss_excluded_when_filter_names_other_providers(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_cve(session, CVE_A)

        result = EnrichmentEngine(session).run_external_enrichment_batch(providers=["virustotal"])

        assert "epss_enriched" not in result
        assert len(respx.calls) == 0

    def test_unknown_provider_filter_still_rejected(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        with pytest.raises(ValueError, match="Unknown enrichment provider"):
            EnrichmentEngine(session).run_external_enrichment_batch(providers=["nope"])

    @respx.mock
    def test_http_error_counts_as_error_not_crash(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        _seed_cve(session, CVE_A)
        _mock_epss_api({CVE_A: ("0.5", "0.9")}).mock(side_effect=httpx.Response(503, text="down"))

        result = EnrichmentEngine(session).run_external_enrichment_batch()

        assert result["errors"] == 1
        assert result["epss_enriched"] == 0

    @respx.mock
    def test_unenriched_only_mode_ignores_stale_rows(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        now = datetime.now(UTC)
        stale = _seed_cve(session, "CVE-2020-0001", epss_enriched_at=now - timedelta(days=30))
        never = _seed_cve(session, "CVE-2020-0003")
        _mock_epss_api({never.cve_id: ("0.3", "0.6")})

        result = EnrichmentEngine(session).run_external_enrichment_batch(include_stale=False)

        assert result["epss_enriched"] == 1
        session.expire_all()
        assert stale.epss is None

    @respx.mock
    def test_force_ignores_fresh_sentinels(self, session, epss_settings):
        from scry.enrichment.engine import EnrichmentEngine

        now = datetime.now(UTC)
        row = _seed_cve(session, CVE_A, epss_enriched_at=now - timedelta(days=1))
        _mock_epss_api({CVE_A: ("0.7", "0.8")})

        result = EnrichmentEngine(session).run_external_enrichment_batch(force=True)

        assert result["epss_enriched"] == 1
        session.expire_all()
        assert row.epss == pytest.approx(0.7)
