"""Mobile browser support and the embedded Orbistrace page.

Phones (iPhone, Samsung Galaxy, Pixel, foldables) previously zoomed every list
page out to 600-1400 px because tables widened the layout, the header wrapped
into ~190 px, dropdowns relied on hover/focus (iOS Safari never focuses a
tapped button), and 13 px inputs triggered iOS focus-zoom.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from scry.config import get_settings
from scry.main import app, orbistrace_src


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestMobileShell:
    def test_viewport_and_mobile_meta(self, client):
        html = client.get("/").text
        assert 'content="width=device-width, initial-scale=1, viewport-fit=cover"' in html
        assert 'name="format-detection" content="telephone=no' in html  # IPs/hashes are not phone links
        assert 'name="theme-color"' in html
        assert 'rel="manifest" href="/static/manifest.webmanifest"' in html
        assert 'rel="apple-touch-icon"' in html

    def test_collapsible_menu_and_tap_dropdowns(self, client):
        html = client.get("/").text
        assert 'class="nav-toggle"' in html and 'aria-controls="nav-links"' in html
        assert 'class="nav-btn" aria-haspopup="true" aria-expanded="false"' in html
        # Hover-only opening is limited to devices that can hover.
        assert "@media (hover: hover) { .nav-dropdown:hover .dropdown-menu" in html

    def test_touch_inputs_avoid_ios_focus_zoom(self, client):
        html = client.get("/").text
        assert "@media (pointer: coarse)" in html and "font-size: 16px" in html

    def test_tables_scroll_in_their_own_box(self, client):
        html = client.get("/").text
        assert ".table-scroll" in html and "wrap.className = cols >= 4" in html

    def test_ioc_search_boxes_are_not_autocorrected(self, client):
        html = client.get("/ui/observables").text
        assert 'type="search" name="q" autocapitalize="none" autocorrect="off" spellcheck="false"' in html

    def test_icons_and_manifest_are_served(self, client):
        r = client.get("/static/manifest.webmanifest")
        assert r.status_code == 200 and r.headers["content-type"].startswith("application/manifest+json")
        assert '"display": "standalone"' in r.text
        for name in ("apple-touch-icon.png", "icon-192.png", "icon-512.png", "icon-maskable-512.png"):
            png = client.get(f"/static/{name}")
            assert png.status_code == 200 and png.content[:8] == b"\x89PNG\r\n\x1a\n"

    def test_html_is_compressed(self, client):
        r = client.get("/ui/observables", headers={"Accept-Encoding": "gzip"})
        assert r.headers.get("content-encoding") == "gzip"

    def test_short_identifiers_never_split(self, client, session, seed_source):
        from scry.models import CVE

        session.add(CVE(cve_id="CVE-2025-61882", kev=True))
        session.commit()
        assert '<code class="nb">CVE-2025-61882</code>' in client.get("/ui/cves").text


class TestOrbistrace:
    def test_menu_item_and_full_height_frame(self, client):
        assert '<a href="/ui/orbistrace"' in client.get("/").text
        page = client.get("/ui/orbistrace").text
        assert 'class="embed-frame"' in page and 'src="https://orbistrace.com/"' in page
        assert 'aria-current="page"' in page
        assert '<main class="embed">' in page
        # Clicks stay inside the frame: no top-level navigation away from Scry.
        sandbox = page.split('sandbox="', 1)[1].split('"', 1)[0]
        assert "allow-scripts" in sandbox and "allow-top-navigation" not in sandbox

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            (None, "https://orbistrace.com/"),
            ("/map?layer=quakes", "https://orbistrace.com/map?layer=quakes"),
            ("//evil.example/x", "https://orbistrace.com/"),
            ("https://evil.example/", "https://orbistrace.com/"),
            ("javascript:alert(1)", "https://orbistrace.com/"),
            ("/\\evil.example", "https://orbistrace.com/"),
        ],
    )
    def test_deep_links_stay_on_orbistrace(self, path, expected):
        assert orbistrace_src("https://orbistrace.com/", path) == expected

    def test_deep_link_param(self, client):
        assert 'src="https://orbistrace.com/map"' in client.get("/ui/orbistrace?path=/map").text

    def test_empty_setting_hides_the_menu(self, client, monkeypatch):
        monkeypatch.setenv("CTI_ORBISTRACE_URL", "")
        get_settings.cache_clear()
        assert "/ui/orbistrace" not in client.get("/").text
        assert client.get("/ui/orbistrace").status_code == 404
