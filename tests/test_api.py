from fastapi.testclient import TestClient

from scry.main import app


def test_health():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


def test_stats_endpoint_returns_counts():
    with TestClient(app) as client:
        r = client.get("/stats")
        assert r.status_code == 200
        body = r.json()
        for k in ("sources", "articles", "observables", "cves"):
            assert k in body


def test_watchlists_and_pirs():
    with TestClient(app) as client:
        assert client.get("/watchlists").status_code == 200
        assert client.get("/pirs").status_code == 200


def test_decay_runs_via_api():
    with TestClient(app) as client:
        r = client.post("/decay/run")
        assert r.status_code == 200
        assert "expired" in r.json()
