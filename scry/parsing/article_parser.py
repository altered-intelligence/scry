"""Article parser.

Order of preference: trafilatura -> readability-lxml -> bs4 fallback.
All of these handle modern article HTML; we keep the dependency footprint
soft so the system still works without them installed.
"""

from __future__ import annotations

from dataclasses import dataclass

from bs4 import BeautifulSoup

from scry.parsing.normalizer import normalize_text


@dataclass
class ParsedArticle:
    title: str
    text: str
    author: str | None
    language: str | None
    canonical_url: str | None
    raw_html: str | None


def parse_article(html: str, url: str | None = None) -> ParsedArticle:
    title = ""
    text = ""
    author: str | None = None
    language: str | None = None
    canonical_url: str | None = None

    if not html:
        return ParsedArticle(title="", text="", author=None, language=None, canonical_url=None, raw_html=None)

    try:
        import trafilatura

        extracted_meta = trafilatura.extract_metadata(html)
        text = (
            trafilatura.extract(
                html, include_comments=False, include_tables=True, favor_recall=True, output_format="txt"
            )
            or ""
        )
        if extracted_meta:
            title = (extracted_meta.title or "").strip()
            author = extracted_meta.author or None
            language = extracted_meta.language
            canonical_url = extracted_meta.url
    except Exception:
        pass

    if not text:
        try:
            from readability import Document

            doc = Document(html)
            title = title or (doc.short_title() or "").strip()
            text_html = doc.summary(html_partial=True)
            text = BeautifulSoup(text_html, "lxml").get_text("\n")
        except Exception:
            pass

    if not text:
        soup = BeautifulSoup(html, "lxml")
        if soup.title and soup.title.string and not title:
            title = soup.title.string.strip()
        for s in soup(["script", "style", "noscript", "iframe"]):
            s.decompose()
        text = soup.get_text("\n")

    if url and not canonical_url:
        soup = BeautifulSoup(html, "lxml")
        link = soup.find("link", rel="canonical")
        if link and link.get("href"):
            canonical_url = link["href"]

    return ParsedArticle(
        title=normalize_text(title),
        text=normalize_text(text),
        author=author,
        language=language,
        canonical_url=canonical_url,
        raw_html=html,
    )
