"""Dashboard Quick links must all resolve, and none may point at the empty feed pages.

Three links used to target the Threat Feeds page with category/network filters; nothing
populates that table any more, so they always landed on "No items match the current
filters". Every Quick link must now return 200 (HTML or the plain-text reports) and
the section must not link into /ui/intel-feeds.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from scry.main import app


def _quick_links(html: str) -> list[tuple[str, str]]:
    block = html.split("<h3>Quick links</h3>", 1)[1].split("</ul>", 1)[0]
    return re.findall(r'<a href="([^"]+)"[^>]*>([^<]+)</a>', block)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_quick_links_section_is_present_and_not_empty(client):
    links = _quick_links(client.get("/").text)
    assert len(links) >= 8


def test_every_quick_link_resolves(client):
    for href, label in _quick_links(client.get("/").text):
        r = client.get(href, follow_redirects=False)
        assert r.status_code == 200, f"{label!r} -> {href} returned {r.status_code}"


def test_no_quick_link_points_at_the_empty_feed_pages(client):
    for href, label in _quick_links(client.get("/").text):
        assert "/ui/intel-feeds/" not in href, f"{label!r} links to an unpopulated feed page"


def test_article_tag_links_filter_by_the_tag(client):
    hrefs = {href for href, _ in _quick_links(client.get("/").text)}
    assert "/ui/articles?tag=ransomware" in hrefs
    assert "/ui/articles?tag=exploited-in-the-wild" in hrefs
    assert client.get("/ui/articles?tag=ransomware").status_code == 200
