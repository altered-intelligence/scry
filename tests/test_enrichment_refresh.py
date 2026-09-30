"""Tests for v0.6.0 step 3: staleness-aware enrichment refresh with force override.

Covers the ``_is_stale`` TTL math (missing/stale/fresh/unparseable), batch
candidate selection (stale + missing but not fresh), oldest-first ordering,
``fresh_skipped``/``refreshed`` counts in the API response, ``force=true``
semantics (bulk + single-record), the UI re-enrich flashes, and the admin
coverage stale counts. HTTP is mocked with respx; no real API calls.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from scry.config import get_settings

VT_IP = "https://www.virustotal.com/api/v3/ip_addresses/{}"

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
        }
    }
}

BASE_IP = "198.51.100.{}"


def _ip(n: int) -> str:
    return BASE_IP.format(n)


def _iso_days_ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


@pytest.fixture(autouse=True)
def _tmp_caches_and_vt_key(monkeypatch, tmp_path):
    """Only VT is keyed (others empty) so batch runs touch only VT; caches tmp."""
    import scry.enrichment.abuseipdb as aipdb_mod
    import scry.enrichment.greynoise as gn_mod
    import scry.enrichment.otx as otx_mod
    import scry.enrichment.virustotal as vt_mod

    for mod, name in [
        (aipdb_mod, "abuseipdb"),
        (gn_mod, "greynoise"),
        (otx_mod, "otx"),
        (vt_mod, "vt"),
    ]:
        monkeypatch.setattr(mod, "CACHE_DIR", tmp_path / name)
    monkeypatch.setenv("CTI_VIRUSTOTAL_API_KEY", "vt-key")
    for var in ("CTI_OTX_API_KEY", "CTI_ABUSEIPDB_API_KEY", "CTI_GREYNOISE_API_KEY"):
        monkeypatch.setenv(var, "")
    monkeypatch.setenv("CTI_VT_RATE_PER_MIN", "1000")
    monkeypatch.setenv("CTI_VT_DAILY_QUOTA", "1000")
    get_settings.cache_clear()


def _seed_ip(session, n: int, enrichment: dict | None = None):
    from scry.models import Observable

    value = _ip(n)
    ob = Observable(type="ipv4", value=value, normalized_value=value, enrichment=enrichment)
    session.add(ob)
    session.commit()
    return ob


def _mock_vt_for_all(respx_mock, recorded: list[str] | None = None):
    """Mock every VT IP lookup; optionally record requested IPs in order."""

    def handler(request):
        if recorded is not None:
            recorded.append(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json=VT_PAYLOAD)

    respx_mock.get(url__regex=r"https://www\.virustotal\.com/api/v3/ip_addresses/.+").mock(
        side_effect=handler
    )


class TestIsStale:
    def test_missing_marker_is_stale(self):
        from scry.enrichment.engine import _is_stale

        now = datetime.now(UTC)
        assert _is_stale({}, "virustotal", 7, now) is True

    def test_old_marker_is_stale(self):
        from scry.enrichment.engine import _is_stale

        now = datetime.now(UTC)
        enrichment = {"virustotal_checked_at": _iso_days_ago(10)}
        assert _is_stale(enrichment, "virustotal", 7, now) is True

    def test_boundary_age_is_fresh(self):
        from scry.enrichment.engine import _is_stale

        now = datetime.now(UTC)
        enrichment = {"virustotal_checked_at": _iso_days_ago(6)}
        assert _is_stale(enrichment, "virustotal", 7, now) is False

    def test_unparseable_marker_is_stale(self):
        from scry.enrichment.engine import _is_stale

        now = datetime.now(UTC)
        for bad in ("not-a-date", "", 12345, None):
            assert _is_stale({"virustotal_checked_at": bad}, "virustotal", 7, now) is True

    def test_naive_iso_treated_as_utc(self):
        from scry.enrichment.engine import _is_stale

        now = datetime.now(UTC)
        enrichment = {"virustotal_checked_at": _iso_days_ago(1).replace("+00:00", "")}
        assert _is_stale(enrichment, "virustotal", 7, now) is False


class TestBatchStaleness:
    @respx.mock
    def test_batch_selects_stale_and_missing_not_fresh(self, session):
        _seed_ip(session, 1)  # missing marker
        _seed_ip(session, 2, {"virustotal_checked_at": _iso_days_ago(10)})  # stale (TTL 7d)
        _seed_ip(session, 3, {"virustotal_checked_at": _iso_days_ago(1)})  # fresh
        _mock_vt_for_all(respx.mock)

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run", params=[("providers", "virustotal")])
        assert r.status_code == 200
        body = r.json()
        assert body["vt_enriched"] == 2  # stale + missing
        assert body["fresh_skipped"] == {"virustotal": 1}
        assert body["refreshed"] == {"virustotal": 1}  # only the stale one re-checked
        assert body["total_candidates"] == 2

    @respx.mock
    def test_oldest_first_ordering(self, session):
        # 30d-old marker, 10d-old marker, missing marker → expect exactly that
        # call order (missing first, then ascending marker age).
        _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(30)})
        _seed_ip(session, 2, {"virustotal_checked_at": _iso_days_ago(10)})
        _seed_ip(session, 3)
        recorded: list[str] = []
        _mock_vt_for_all(respx.mock, recorded=recorded)

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run", params=[("providers", "virustotal")])
        assert r.status_code == 200
        assert r.json()["vt_enriched"] == 3
        assert recorded == [_ip(3), _ip(1), _ip(2)]

    @respx.mock
    def test_force_reenriches_fresh_records(self, session):
        _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(1)})  # fresh
        _mock_vt_for_all(respx.mock)

        from scry.main import app

        with TestClient(app) as client:
            r = client.post("/enrichment/run", params=[("providers", "virustotal"), ("force", "true")])
        body = r.json()
        assert body["vt_enriched"] == 1
        assert body["fresh_skipped"] == {}  # nobody was skipped as fresh
        assert body["refreshed"] == {"virustotal": 1}

    @respx.mock
    def test_unenriched_mode_skips_stale_records(self, session):
        """include_stale=False (UI 'unenriched' mode): stale markers left alone."""
        _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(30)})  # stale
        _seed_ip(session, 2)  # missing
        _mock_vt_for_all(respx.mock)

        from scry.enrichment.engine import EnrichmentEngine

        engine = EnrichmentEngine(session)
        result = engine.run_external_enrichment_batch(limit=50, providers=["virustotal"], include_stale=False)
        assert result["vt_enriched"] == 1  # only the never-checked one
        assert result["total_candidates"] == 1
        assert result["fresh_skipped"] == {}  # stale ≠ fresh


class TestSingleRecordForce:
    @respx.mock
    def test_fresh_record_skipped_without_network(self, session):
        marker = _iso_days_ago(1)
        ob = _seed_ip(session, 1, {"virustotal_checked_at": marker})
        _mock_vt_for_all(respx.mock)

        from scry.enrichment.engine import EnrichmentEngine

        engine = EnrichmentEngine(session)
        result = engine.enrich_observable_external(ob, providers=["virustotal"])
        assert result.fresh_skipped == ["virustotal"]
        assert "virustotal skipped: fresh" in "; ".join(result.rationale)
        assert len(respx.calls) == 0  # no provider call
        # marker untouched
        assert ob.enrichment["virustotal_checked_at"] == marker

    @respx.mock
    def test_force_calls_provider(self, session):
        ob = _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(1)})
        _mock_vt_for_all(respx.mock)

        from scry.enrichment.engine import EnrichmentEngine

        engine = EnrichmentEngine(session)
        result = engine.enrich_observable_external(ob, providers=["virustotal"], force=True)
        assert result.fresh_skipped == []
        assert len(respx.calls) == 1
        assert ob.enrichment["virustotal"]["malicious"] == 12
        # marker moved forward
        new_age = datetime.now(UTC) - datetime.fromisoformat(ob.enrichment["virustotal_checked_at"])
        assert new_age.total_seconds() < 60

    @respx.mock
    def test_missing_marker_enriches_by_default(self, session):
        ob = _seed_ip(session, 1)
        _mock_vt_for_all(respx.mock)

        from scry.enrichment.engine import EnrichmentEngine

        engine = EnrichmentEngine(session)
        result = engine.enrich_observable_external(ob, providers=["virustotal"])
        assert result.fresh_skipped == []
        assert len(respx.calls) == 1


# ------------------------- UI -------------------------


def _signed_client_with_vt_key(session):
    from scry.auth.passwords import hash_password
    from scry.auth.sessions import SESSION_COOKIE, create_session
    from scry.db import session_scope
    from scry.enrichment.user_keys import set_key
    from scry.main import _admin_csrf_token, app
    from scry.models import User

    with session_scope() as s:
        user = User(
            username="refresh-user",
            email="refresh@example.com",
            role="user",
            status="active",
            password_hash=hash_password("S3cure!pass"),
        )
        s.add(user)
        s.flush()
        set_key(s, user.id, "virustotal", "personal-vt-key")
        raw = create_session(s, user, ip="127.0.0.1", user_agent="pytest")
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE, raw)
    return client, _admin_csrf_token(raw)


class TestUiReEnrich:
    @respx.mock
    def test_reenrich_stale_mode_flash(self, session):
        _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(10)})
        _mock_vt_for_all(respx.mock)
        client, csrf = _signed_client_with_vt_key(session)

        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf, "mode": "stale"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        flash = parse_qs(urlparse(r.headers["location"]).query)["flash"][0]
        assert "Re-enrich stale (my keys)" in flash
        assert "virustotal enriched 1" in flash
        assert "virustotal re-enriched stale 1" in flash

    @respx.mock
    def test_force_mode_reenriches_fresh_and_flashes(self, session):
        _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(1)})
        _mock_vt_for_all(respx.mock)
        client, csrf = _signed_client_with_vt_key(session)

        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf, "mode": "force"},
            follow_redirects=False,
        )
        flash = parse_qs(urlparse(r.headers["location"]).query)["flash"][0]
        assert "Force re-enrich all (my keys)" in flash
        assert "virustotal enriched 1" in flash
        assert "fresh (skipped)" not in flash

    @respx.mock
    def test_unenriched_mode_flash_counts_fresh_skipped(self, session):
        _seed_ip(session, 1, {"virustotal_checked_at": _iso_days_ago(1)})  # fresh
        _seed_ip(session, 2)  # missing
        _mock_vt_for_all(respx.mock)
        client, csrf = _signed_client_with_vt_key(session)

        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf, "mode": "unenriched"},
            follow_redirects=False,
        )
        flash = parse_qs(urlparse(r.headers["location"]).query)["flash"][0]
        assert "Enrich unenriched (my keys)" in flash
        assert "fresh (skipped): virustotal 1" in flash

    def test_unknown_mode_rejected(self, session):
        client, csrf = _signed_client_with_vt_key(session)
        r = client.post(
            "/ui/observables/enrich-unenriched",
            data={"csrf": csrf, "mode": "nonsense"},
            follow_redirects=False,
        )
        flash = parse_qs(urlparse(r.headers["location"]).query)["flash"][0]
        assert "Unknown enrichment mode" in flash

    def test_observables_page_shows_reenrich_buttons(self, session):
        client, _ = _signed_client_with_vt_key(session)
        r = client.get("/ui/observables")
        assert "Enrich unenriched (my keys)" in r.text
        assert "Re-enrich stale (my keys)" in r.text
        assert "Force re-enrich all (my keys)" in r.text

    def test_detail_page_shows_provider_age(self, session):
        _seed_ip(
            session,
            1,
            {
                "virustotal_checked_at": _iso_days_ago(2),
                "otx_checked_at": _iso_days_ago(40),
            },
        )
        client, _ = _signed_client_with_vt_key(session)
        r = client.get("/ui/observables/1")
        assert r.status_code == 200
        assert "2d ago" in r.text  # VT age (humanized)
        assert "40d ago" in r.text  # OTX age
        assert ">never<" in r.text  # AbuseIPDB / GreyNoise never checked
        assert "Re-check VirusTotal now (uses your quota)" in r.text


# ------------------------- admin coverage -------------------------


class TestAdminStaleCounts:
    def test_coverage_counts_stale_per_provider(self, session):
        from scry.auth.passwords import hash_password
        from scry.auth.sessions import SESSION_COOKIE, create_session
        from scry.db import session_scope
        from scry.main import app
        from scry.models import Observable, User

        with session_scope() as s:
            admin = User(
                username="root",
                email="root@example.com",
                role="admin",
                status="active",
                password_hash=hash_password("S3cure!pass"),
            )
            s.add(admin)
            s.flush()
            raw = create_session(s, admin, ip="127.0.0.1", user_agent="pytest")
            # ob1: never checked → stale for every provider.
            s.add(Observable(type="ipv4", value=_ip(1), normalized_value=_ip(1)))
            # ob2: VT fresh (1d < 7d); others never checked → stale.
            s.add(
                Observable(
                    type="ipv4",
                    value=_ip(2),
                    normalized_value=_ip(2),
                    enrichment={"virustotal_checked_at": _iso_days_ago(1)},
                )
            )
            # ob3: VT fresh (5d < 7d) but GreyNoise stale (5d > 3d); OTX/AIPDB stale.
            s.add(
                Observable(
                    type="ipv4",
                    value=_ip(3),
                    normalized_value=_ip(3),
                    enrichment={
                        "virustotal_checked_at": _iso_days_ago(5),
                        "greynoise_checked_at": _iso_days_ago(5),
                    },
                )
            )
            # ob4: email type — not valid for any external provider → never stale.
            s.add(Observable(type="email", value="a@b.c", normalized_value="a@b.c"))
            s.commit()

        client = TestClient(app)
        client.cookies.set(SESSION_COOKIE, raw)
        r = client.get("/admin")
        assert r.status_code == 200
        # stale counts: VT 1, OTX 3, AbuseIPDB 3, GreyNoise 3
        assert r.text.count('<span class="badge warn">3</span>') == 3
        assert r.text.count('<span class="badge warn">1</span>') == 1
