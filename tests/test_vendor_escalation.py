"""Tests for v0.6.0 step 2 — vendor-verdict alert escalation.

Enrichment JSON shapes below mirror exactly what scry/enrichment/{virustotal,
abuseipdb,greynoise}.py store via their ``_summarize`` output (see
tests/test_enrichment_providers.py fixtures).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from scry.alerting.engine import AlertEngine
from scry.config import get_settings
from scry.main import app
from scry.models import Alert, Observable

VT_STATS_HIGH = {"malicious": 52, "suspicious": 3, "harmless": 40, "undetected": 5}
VT_STATS_LOW_RATIO = {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 10}
VT_STATS_LOW_VOTES = {"malicious": 9, "suspicious": 0, "harmless": 0, "undetected": 1}

VT_CONFIRMED = {
    "virustotal": {
        "last_analysis_stats": VT_STATS_HIGH,
        **VT_STATS_HIGH,
        "reputation": -100,
        "last_analysis_date": 1714521600,
    },
    "virustotal_checked_at": "2024-05-01T12:00:00+00:00",
}

VT_LOW_RATIO = {
    "virustotal": {
        "last_analysis_stats": VT_STATS_LOW_RATIO,
        **VT_STATS_LOW_RATIO,
        "reputation": -50,
    },
    "virustotal_checked_at": "2024-05-01T12:00:00+00:00",
}

VT_LOW_VOTES = {
    "virustotal": {
        "last_analysis_stats": VT_STATS_LOW_VOTES,
        **VT_STATS_LOW_VOTES,
        "reputation": -10,
    },
    "virustotal_checked_at": "2024-05-01T12:00:00+00:00",
}

AIPDB_80 = {
    "abuseipdb": {
        "abuse_confidence_score": 80,
        "country_code": "RU",
        "isp": "Example Telecom Ltd",
        "total_reports": 42,
        "last_reported_at": "2024-05-01T12:00:00+00:00",
        "num_distinct_users": 12,
    },
    "abuseipdb_checked_at": "2024-05-01T12:00:00+00:00",
}

GN_MALICIOUS = {
    "greynoise": {
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "shady scanner",
        "last_seen": "2024-05-01",
        "link": "https://viz.greynoise.io/ip/198.51.100.9",
        "message": "Success",
    },
    "greynoise_checked_at": "2024-05-01T12:00:00+00:00",
}

GN_BENIGN = {
    "greynoise": {
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Example CDN",
        "last_seen": "2024-05-01",
        "message": "Success",
    },
    "greynoise_checked_at": "2024-05-01T12:00:00+00:00",
}

GN_UNKNOWN = {
    "greynoise": {
        "noise": False,
        "riot": False,
        "classification": "unknown",
        "message": "Success",
    },
    "greynoise_checked_at": "2024-05-01T12:00:00+00:00",
}


def make_ob(session, enrichment=None, *, value="198.51.100.9", risk_score=20.0, conf=50):
    ob = Observable(
        type="ipv4",
        value=value,
        normalized_value=value,
        risk_score=risk_score,
        maliciousness_confidence=conf,
        enrichment=enrichment or {},
    )
    session.add(ob)
    session.commit()
    return ob


def vendor_alerts(session) -> list[Alert]:
    return [
        a for a in session.scalars(select(Alert)).all() if a.trigger == "vendor_confirmed_malicious"
    ]


class TestVirusTotal:
    def test_confirmed_over_thresholds(self, session):
        ob = make_ob(session, VT_CONFIRMED)
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 1
        a = alerts[0]
        assert a.trigger == "vendor_confirmed_malicious"
        assert a.title == f"virustotal confirms malicious: ipv4 {ob.normalized_value}"
        assert a.related["observable_id"] == ob.id
        assert a.related["type"] == "ipv4"
        assert a.related["value"] == ob.normalized_value
        assert a.related["provider"] == "virustotal"
        assert "52/100" in a.related["verdict"]
        assert a.why_it_matters == "Vendor verdict confirms this indicator is malicious in the wild."
        assert a.recommended_action == (
            "Block/hunt at the edge; add to denylists; sweep for related infrastructure."
        )
        assert a.dedup_key.startswith("vendor_conf:")

    def test_votes_pass_but_ratio_fails(self, session):
        make_ob(session, VT_LOW_RATIO)  # 12 votes >= 10 but ratio 12/73 < 0.5
        created = AlertEngine(session).evaluate()
        assert not [a for a in created if a.trigger == "vendor_confirmed_malicious"]

    def test_ratio_passes_but_votes_fail(self, session):
        make_ob(session, VT_LOW_VOTES)  # ratio 0.9 but 9 votes < 10
        created = AlertEngine(session).evaluate()
        assert not [a for a in created if a.trigger == "vendor_confirmed_malicious"]

    def test_thresholds_overridable_via_env(self, session, monkeypatch):
        monkeypatch.setenv("CTI_VT_ESCALATE_MIN_DETECTIONS", "5")
        monkeypatch.setenv("CTI_VT_ESCALATE_MIN_RATIO", "0.4")
        get_settings.cache_clear()
        make_ob(session, VT_LOW_RATIO)  # 12 votes, ratio ~0.164 — still under 0.4
        created = AlertEngine(session).evaluate()
        assert not [a for a in created if a.trigger == "vendor_confirmed_malicious"]

        session2_ob = make_ob(
            session,
            {
                "virustotal": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 6, "undetected": 1},
                    "malicious": 5,
                    "suspicious": 0,
                    "harmless": 6,
                    "undetected": 1,
                },
                "virustotal_checked_at": "2024-05-01T12:00:00+00:00",
            },
            value="198.51.100.10",
        )
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 1
        assert alerts[0].related["observable_id"] == session2_ob.id


class TestAbuseIPDB:
    def test_score_80_escalates(self, session):
        ob = make_ob(session, AIPDB_80)
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 1
        assert alerts[0].related["provider"] == "abuseipdb"
        assert "80/100" in alerts[0].related["verdict"]
        assert alerts[0].confidence == ob.maliciousness_confidence

    def test_score_79_does_not_escalate(self, session):
        below = {
            "abuseipdb": {**AIPDB_80["abuseipdb"], "abuse_confidence_score": 79},
            "abuseipdb_checked_at": "2024-05-01T12:00:00+00:00",
        }
        make_ob(session, below)
        created = AlertEngine(session).evaluate()
        assert not [a for a in created if a.trigger == "vendor_confirmed_malicious"]

    def test_min_score_overridable_via_env(self, session, monkeypatch):
        monkeypatch.setenv("CTI_ABUSEIPDB_ESCALATE_MIN_SCORE", "85")
        get_settings.cache_clear()
        make_ob(session, AIPDB_80)  # 80 < 85
        created = AlertEngine(session).evaluate()
        assert not [a for a in created if a.trigger == "vendor_confirmed_malicious"]


class TestGreyNoise:
    def test_malicious_escalates(self, session):
        make_ob(session, GN_MALICIOUS)
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 1
        assert alerts[0].related["provider"] == "greynoise"
        assert alerts[0].related["verdict"] == "classification: malicious"

    @pytest.mark.parametrize("enrichment", [GN_BENIGN, GN_UNKNOWN])
    def test_benign_or_unknown_does_not_escalate(self, session, enrichment):
        make_ob(session, enrichment)
        created = AlertEngine(session).evaluate()
        assert not [a for a in created if a.trigger == "vendor_confirmed_malicious"]

    def test_classification_overridable_via_env(self, session, monkeypatch):
        monkeypatch.setenv("CTI_GN_ESCALATE_CLASSIFICATION", "benign")
        get_settings.cache_clear()
        make_ob(session, GN_BENIGN)
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 1
        assert alerts[0].related["provider"] == "greynoise"


class TestRiskBump:
    def test_bump_applied_once(self, session):
        ob = make_ob(session, VT_CONFIRMED, risk_score=20.0)
        AlertEngine(session).evaluate()
        assert ob.risk_score == pytest.approx(30.0)
        assert "virustotal_escalated" in ob.enrichment

    def test_bump_capped_at_100(self, session):
        ob = make_ob(session, VT_CONFIRMED, risk_score=95.0)
        AlertEngine(session).evaluate()
        assert ob.risk_score == 100.0

    def test_second_evaluate_dedups_and_does_not_rebump(self, session):
        ob = make_ob(session, VT_CONFIRMED, risk_score=20.0)
        engine = AlertEngine(session)
        first = engine.evaluate()
        assert len([a for a in first if a.trigger == "vendor_confirmed_malicious"]) == 1

        second = AlertEngine(session).evaluate()
        assert second == []
        session.expire_all()
        assert ob.risk_score == pytest.approx(30.0)  # no re-bump
        assert len(vendor_alerts(session)) == 1

    def test_preexisting_marker_no_bump_but_alert_created(self, session):
        enrichment = dict(VT_CONFIRMED)
        enrichment["virustotal_escalated"] = "2024-04-01T00:00:00+00:00"
        ob = make_ob(session, enrichment, risk_score=55.0)
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 1
        assert ob.risk_score == 55.0  # already escalated earlier; no double bump

    def test_multiple_providers_bump_per_provider(self, session):
        enrichment = {}
        for part in (VT_CONFIRMED, GN_MALICIOUS):
            enrichment.update(part)
        ob = make_ob(session, enrichment, risk_score=40.0)
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert len(alerts) == 2
        assert len({a.dedup_key for a in alerts}) == 2
        assert {a.related["provider"] for a in alerts} == {"virustotal", "greynoise"}
        session.expire_all()
        assert ob.risk_score == pytest.approx(60.0)  # +10 per confirmed provider
        assert "virustotal_escalated" in ob.enrichment
        assert "greynoise_escalated" in ob.enrichment

    def test_no_enrichment_no_alert_no_bump(self, session):
        ob = make_ob(session, None, risk_score=20.0)
        created = AlertEngine(session).evaluate()
        assert created == []
        assert ob.risk_score == 20.0

    def test_severity_follows_bumped_risk_score(self, session):
        make_ob(session, VT_CONFIRMED, risk_score=65.0)  # 65 + 10 = 75 → high
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert alerts[0].severity == "high"

    def test_severity_medium_below_70(self, session):
        make_ob(session, VT_CONFIRMED, risk_score=20.0)  # 20 + 10 = 30 → medium
        created = AlertEngine(session).evaluate()
        alerts = [a for a in created if a.trigger == "vendor_confirmed_malicious"]
        assert alerts[0].severity == "medium"


class TestAlertFields:
    def test_dedup_key_stable_and_distinct_per_provider(self, session):
        enrichment = {}
        for part in (VT_CONFIRMED, AIPDB_80):
            enrichment.update(part)
        make_ob(session, enrichment)
        AlertEngine(session).evaluate()
        alerts = vendor_alerts(session)
        assert len(alerts) == 2
        keys = {a.dedup_key for a in alerts}
        assert len(keys) == 2
        assert all(k.startswith("vendor_conf:") for k in keys)
        # Same observable + provider on a second run dedups to zero new alerts.
        assert AlertEngine(session).evaluate() == []

    def test_not_found_results_do_not_escalate(self, session):
        enrichment = {
            "virustotal": {"not_found": True},
            "virustotal_checked_at": "2024-05-01T12:00:00+00:00",
            "abuseipdb": {"not_found": True},
            "abuseipdb_checked_at": "2024-05-01T12:00:00+00:00",
            "greynoise": {"not_found": True},
            "greynoise_checked_at": "2024-05-01T12:00:00+00:00",
        }
        make_ob(session, enrichment)
        assert AlertEngine(session).evaluate() == []


class TestApiPath:
    def test_alerts_run_endpoint_creates_vendor_alert(self, session):
        make_ob(session, VT_CONFIRMED)
        client = TestClient(app)
        resp = client.post("/alerts/run")
        assert resp.status_code == 200
        assert resp.json()["created"] >= 1
        alerts = vendor_alerts(session)
        assert len(alerts) == 1
        assert alerts[0].delivered is False  # outbound disabled in tests
