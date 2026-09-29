"""Tests for UI feature additions: timeago filter, bulk review actions,
dashboard collect control, and the gated AI search panel.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from scry.db import session_scope
from scry.main import _timeago, app
from scry.models import AnalystReview


def _seed_reviews(n: int = 2, status: str = "open") -> list[int]:
    with session_scope() as s:
        ids = []
        for i in range(n):
            r = AnalystReview(
                item_type="observable",
                item_id=i + 1,
                reason=f"test reason {i}",
                confidence=70,
                status=status,
            )
            s.add(r)
            s.flush()
            ids.append(r.id)
        s.commit()
        return ids


class TestTimeago:
    def test_none_renders_dash(self):
        assert "—" in str(_timeago(None))

    def test_just_now(self):
        assert "just now" in str(_timeago(datetime.now(UTC)))

    def test_hours(self):
        dt = datetime.now(UTC) - timedelta(hours=3)
        assert "3h ago" in str(_timeago(dt))

    def test_days(self):
        dt = datetime.now(UTC) - timedelta(days=2)
        assert "2d ago" in str(_timeago(dt))

    def test_naive_assumed_utc(self):
        dt = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=5)
        assert "5m ago" in str(_timeago(dt))

    def test_renders_time_element_with_absolute_title(self):
        dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        html = str(_timeago(dt))
        assert html.startswith('<time datetime="2026-01-01T12:00:00+00:00"')
        assert 'title="2026-01-01 12:00:00 UTC"' in html

    def test_future_clamps_to_zero(self):
        dt = datetime.now(UTC) + timedelta(hours=1)
        assert "just now" in str(_timeago(dt))


class TestBulkReviews:
    def test_bulk_approve_closes_open_reviews(self):
        ids = _seed_reviews(2)
        with TestClient(app) as client:
            r = client.post(
                "/ui/reviews/bulk",
                data={"review_ids": [str(i) for i in ids], "action": "approve"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "flash=2+reviews+approved" in r.headers["location"]
        with session_scope() as s:
            rows = [s.get(AnalystReview, i) for i in ids]
            assert all(row.status == "closed" for row in rows)
            assert all(row.disposition == "true_positive" for row in rows)
            assert all(row.reviewed_at is not None for row in rows)

    def test_bulk_reject(self):
        ids = _seed_reviews(1)
        with TestClient(app) as client:
            client.post(
                "/ui/reviews/bulk",
                data={"review_ids": [str(ids[0])], "action": "reject"},
                follow_redirects=False,
            )
        with session_scope() as s:
            row = s.get(AnalystReview, ids[0])
            assert row.status == "closed"
            assert row.disposition == "false_positive"

    def test_bulk_skips_closed_reviews(self):
        ids = _seed_reviews(1, status="closed")
        with TestClient(app) as client:
            r = client.post(
                "/ui/reviews/bulk",
                data={"review_ids": [str(ids[0])], "action": "approve"},
                follow_redirects=False,
            )
            assert "flash=0+reviews+approved" in r.headers["location"]

    def test_bulk_unknown_id_is_graceful(self):
        with TestClient(app) as client:
            r = client.post(
                "/ui/reviews/bulk",
                data={"review_ids": ["999999"], "action": "approve"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "flash=0+reviews+approved" in r.headers["location"]

    def test_bulk_invalid_action_flashes_error(self):
        with TestClient(app) as client:
            r = client.post(
                "/ui/reviews/bulk",
                data={"review_ids": ["1"], "action": "nuke"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "flash_kind=error" in r.headers["location"]

    def test_review_queue_renders_checkbox_column(self):
        _seed_reviews(1)
        with TestClient(app) as client:
            r = client.get("/ui/reviews")
            assert r.status_code == 200
            assert 'name="review_ids"' in r.text
            assert 'id="select-all"' in r.text


class TestDashboardCollect:
    def test_dashboard_has_collect_button_and_last_collected(self):
        with TestClient(app) as client:
            r = client.get("/")
            assert r.status_code == 200
            assert 'action="/ui/ingest/run"' in r.text
            assert "Last collected: never" in r.text

    def test_dashboard_shows_last_collected_after_ingest(self):
        from scry.models import Article, Source

        with session_scope() as s:
            src = Source(
                name="T",
                type="vendor_blog",
                url="https://example.com",
                enabled=False,
                collection_policy="safe_public_web",
            )
            s.add(src)
            s.flush()
            s.add(
                Article(
                    source_id=src.id,
                    title="t",
                    url="https://example.com/a",
                    ingested_at=datetime.now(UTC),
                )
            )
            s.commit()
        with TestClient(app) as client:
            r = client.get("/")
            assert "Last collected:" in r.text
            assert "just now" in r.text


class TestAISearchGate:
    def test_ai_panel_hidden_by_default(self):
        with TestClient(app) as client:
            r = client.get("/ui/search")
            assert r.status_code == 200
            assert "ai-search-section" not in r.text
            assert "ai-panel" not in r.text

    def test_ai_panel_shown_when_enabled(self, monkeypatch):
        monkeypatch.setenv("CTI_ENABLE_AI_SEARCH", "true")
        from scry import config as _config

        _config.get_settings.cache_clear()
        try:
            with TestClient(app) as client:
                r = client.get("/ui/search")
                assert r.status_code == 200
                # self-contained inline panel: toggle, status pill, no dead static refs
                assert 'id="ai-panel"' in r.text
                assert 'id="ai-enabled-toggle"' in r.text
                assert "scry-ai-enabled" in r.text
                assert "/api/ai/status" in r.text
                assert "/api/ai/ask" in r.text
                assert "ai_chat.js" not in r.text
                assert "ai_chat.css" not in r.text
                assert "/ui/settings/llms" not in r.text
        finally:
            _config.get_settings.cache_clear()


class TestSourcesPage:
    def test_sources_page_lists_registry(self):
        # App startup syncs config/sources.yaml into the (test) DB.
        with TestClient(app) as client:
            r = client.get("/ui/sources")
            assert r.status_code == 200
            body = r.text
            assert "CISA AIS (TAXII)" in body
            assert "Google Cloud Threat Intelligence (Mandiant)" in body
            # summary strip shows totals
            assert "28 total" in body
            # both enabled and disabled badges present
            assert '<span class="badge good">enabled</span>' in body
            assert '<span class="badge dim">disabled</span>' in body

    def test_sources_page_shows_disabled_state_for_sophos_and_ais(self):
        from sqlalchemy import select

        from scry.models import Source

        with session_scope() as s:
            # ensure registry synced for this test's DB
            from scry.ingestion.source_registry import SourceRegistry

            SourceRegistry(s).sync_from_yaml()
            sophos = s.scalar(select(Source).where(Source.name == "Sophos X-Ops"))
            ais = s.scalar(select(Source).where(Source.name == "CISA AIS (TAXII)"))
            assert sophos is not None and sophos.enabled is False
            assert ais is not None and ais.enabled is False

    def test_nav_contains_sources_link(self):
        with TestClient(app) as client:
            r = client.get("/")
            assert 'href="/ui/sources"' in r.text


class TestNavAndTheme:
    def test_nav_has_theme_toggle_and_no_coming_soon(self):
        with TestClient(app) as client:
            r = client.get("/")
            assert 'id="theme-toggle"' in r.text
            assert "Coming Soon" not in r.text
            assert 'name="color-scheme" content="dark light"' in r.text

    def test_flash_banner_renders(self):
        with TestClient(app) as client:
            r = client.get("/?flash=hello&flash_kind=success")
            assert r.status_code == 200
            assert 'class="flash success"' in r.text
            assert "hello" in r.text
