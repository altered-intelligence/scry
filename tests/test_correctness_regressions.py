"""Regression tests for the correctness/performance hardening pass.

Covers: JSON tag filters on SQLite (multi-tag rows, LIKE escaping),
pipeline reprocessing idempotency, last_reported monotonicity, in-feed
duplicate URLs, the default Manual source for ad-hoc ingests, cluster and
conflict re-run dedup, migration index backfills, alias-resolution type
gating, benign-infrastructure suffix matching, and AI prompt budgeting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select

import scry.api.ai as ai_mod
import scry.ingestion.ingest_engine as ingest_engine_module
from scry.ai.providers.base import ChatChunk
from scry.alerting import AlertEngine
from scry.alias_resolution import resolve_canonical
from scry.clustering import cluster_articles
from scry.conflicts import detect_conflicts
from scry.db import tag_filter
from scry.extraction.ioc_extractor import IOCExtractor
from scry.ingestion import IngestionEngine
from scry.ingestion.fetcher import FetchResult
from scry.main import app
from scry.migrations import run_migrations
from scry.models import (
    AnalystReview,
    Article,
    AttackMapping,
    Claim,
    Cluster,
    Conflict,
    EntityMention,
    Observable,
    ObservableMention,
    Relationship,
    Source,
)
from scry.pipeline import CTIPipeline


def _article(session, source, url: str, *, tags=None, text: str = "", published_at=None) -> Article:
    art = Article(
        source_id=source.id,
        title=f"Article {url}",
        url=url,
        ingested_at=datetime.now(UTC),
        published_at=published_at or datetime.now(UTC),
        extracted_text=text,
        tags=list(tags or []),
    )
    session.add(art)
    session.commit()
    return art


# ------------------------- JSON tag filters (SQLite) -------------------------


class TestTagFilters:
    def test_multi_tag_articles_match(self, session, seed_source):
        multi = _article(session, seed_source, "https://example.com/multi", tags=["ransomware", "c2"])
        single = _article(session, seed_source, "https://example.com/single", tags=["ransomware"])
        _article(session, seed_source, "https://example.com/other", tags=["phishing"])

        rows = session.scalars(select(Article).where(tag_filter(Article.tags, "ransomware"))).all()
        assert {a.id for a in rows} == {multi.id, single.id}

    def test_like_metacharacters_are_escaped(self, session, seed_source):
        underscore = _article(session, seed_source, "https://example.com/under", tags=["a_c"])
        _article(session, seed_source, "https://example.com/plain", tags=["abc"])

        rows = session.scalars(select(Article).where(tag_filter(Article.tags, "a_c"))).all()
        assert [a.id for a in rows] == [underscore.id]
        assert session.scalars(select(Article).where(tag_filter(Article.tags, "%"))).all() == []

    def test_ransomware_alert_fires_for_multi_tag_article(self, session, seed_source):
        multi = _article(session, seed_source, "https://example.com/rw-multi", tags=["ransomware", "c2"])
        single = _article(session, seed_source, "https://example.com/rw-single", tags=["ransomware"])

        created = AlertEngine(session).evaluate()
        rw_urls = {a.related["article_id"] for a in created if a.trigger == "ransomware_activity"}
        assert rw_urls == {multi.id, single.id}

    def test_articles_endpoint_tag_returns_multi_tag_rows(self, session, seed_source):
        multi = _article(session, seed_source, "https://example.com/api-multi", tags=["ransomware", "c2"])
        _article(session, seed_source, "https://example.com/api-other", tags=["phishing"])
        with TestClient(app) as client:
            r = client.get("/articles", params={"tag": "ransomware"})
            assert r.status_code == 200
            ids = {row["id"] for row in r.json()}
            assert multi.id in ids

    def test_observables_endpoint_tag_matches_multi_tag_rows(self, session, seed_source):
        ob = Observable(
            type="domain",
            value="evil.example",
            normalized_value="evil.example",
            tags=["malware", "ransomware"],
        )
        session.add(ob)
        session.commit()
        with TestClient(app) as client:
            r = client.get("/observables", params={"tag": "malware"})
            assert r.status_code == 200
            assert ob.id in {row["id"] for row in r.json()}


# ------------------------- pipeline idempotency -------------------------


def _derived_counts(session) -> dict[str, int]:
    models = (ObservableMention, EntityMention, Claim, Relationship, AttackMapping, AnalystReview)
    return {m.__tablename__: session.scalar(select(func.count(m.id))) or 0 for m in models}


class TestPipelineReprocessing:
    def test_second_run_produces_identical_counts(self, session, seed_source, fixture_dir):
        art = _article(
            session,
            seed_source,
            "https://example.com/reprocess",
            text=(fixture_dir / "ransomware.txt").read_text(),
        )
        pipeline = CTIPipeline(session)
        pipeline.process_article(art)
        first = _derived_counts(session)
        assert first["observable_mentions"] > 0
        assert first["claims"] > 0

        pipeline.process_article(art)  # reprocess (fetch-full / extract / version bump)
        pipeline.process_article(art)
        assert _derived_counts(session) == first

    def test_last_reported_never_moves_backwards(self, session, seed_source):
        text = "The botnet used 185.220.101.47 for command and control."
        newer = _article(
            session,
            seed_source,
            "https://example.com/newer",
            text=text,
            published_at=datetime(2026, 1, 10, tzinfo=UTC),
        )
        CTIPipeline(session).process_article(newer)
        ob = session.scalar(select(Observable).where(Observable.normalized_value == "185.220.101.47"))
        assert ob is not None
        assert ob.last_reported.replace(tzinfo=UTC) == datetime(2026, 1, 10, tzinfo=UTC)

        # Simulate a fresh session: SQLite round-trips datetimes as naive.
        session.expire_all()
        older = _article(
            session,
            seed_source,
            "https://example.com/older",
            text=text,
            published_at=datetime(2026, 1, 5, tzinfo=UTC),
        )
        CTIPipeline(session).process_article(older)
        ob = session.scalar(select(Observable).where(Observable.normalized_value == "185.220.101.47"))
        assert ob.last_reported.replace(tzinfo=UTC) == datetime(2026, 1, 10, tzinfo=UTC)


# ------------------------- feed ingest -------------------------


def _rss(*, links: list[str]) -> str:
    published = format_datetime(datetime.now(UTC) - timedelta(hours=1))
    items = "".join(
        f"<item><title>item-{i}</title><link>{link}</link><pubDate>{published}</pubDate></item>"
        for i, link in enumerate(links)
    )
    return (
        '<?xml version="1.0"?>\n<rss version="2.0"><channel>'
        "<title>test</title><link>https://example.com/</link><description>d</description>"
        + items
        + "</channel></rss>"
    )


def _patch_fetcher(monkeypatch, text: str, url: str = "https://example.com/blog/feed") -> None:
    result = FetchResult(
        url=url,
        status_code=200,
        content=text.encode(),
        text=text,
        headers={"content-type": "application/rss+xml"},
        content_hash="abc",
    )

    class _FakeFetcher:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def fetch(self, url, **kwargs):
            return result

    monkeypatch.setattr(ingest_engine_module, "SafeFetcher", _FakeFetcher)


class TestFeedIngest:
    async def test_repeated_url_in_feed_does_not_nuke_the_feed(self, session, seed_source, monkeypatch):
        """A feed listing the same URL twice must still ingest the unique articles."""
        dup = "https://example.com/dup"
        _patch_fetcher(monkeypatch, _rss(links=[dup, "https://example.com/uniq", dup]))
        engine = IngestionEngine(session)
        res = await engine.ingest_source(seed_source)
        assert res["articles"] == 2
        urls = {a.url for a in session.scalars(select(Article)).all()}
        assert urls == {dup, "https://example.com/uniq"}


class TestManualSource:
    async def test_ingest_url_without_source_uses_manual_source(self, session, monkeypatch):
        _patch_fetcher(monkeypatch, "<html><body>manual ingest</body></html>", url="https://example.com/m1")
        engine = IngestionEngine(session)
        art = await engine.ingest_url("https://example.com/m1")
        assert art is not None
        src = session.get(Source, art.source_id)
        assert src is not None
        assert src.name == "Manual"
        assert src.type == "manual"
        assert src.baseline_confidence == 50
        assert src.collection_policy == "safe_public_web"

    async def test_ingest_url_endpoint_without_source_id_returns_200(self, session, monkeypatch):
        _patch_fetcher(monkeypatch, "<html><body>manual ingest</body></html>", url="https://example.com/m2")
        with TestClient(app) as client:
            r = client.post("/ingest/url", json={"url": "https://example.com/m2"})
            assert r.status_code == 200
            assert r.json()["status"] == "ok"
        art = session.scalar(select(Article).where(Article.url == "https://example.com/m2"))
        assert art is not None
        assert session.get(Source, art.source_id).name == "Manual"


# ------------------------- clusters / conflicts re-run dedup -------------------------


class TestClusterDedup:
    def test_second_run_replaces_instead_of_duplicating(self, session, seed_source):
        a1 = _article(session, seed_source, "https://example.com/c1")
        a2 = _article(session, seed_source, "https://example.com/c2")
        ob = Observable(type="domain", value="shared.example", normalized_value="shared.example")
        session.add(ob)
        session.flush()
        session.add_all(
            [
                ObservableMention(observable_id=ob.id, article_id=a1.id),
                ObservableMention(observable_id=ob.id, article_id=a2.id),
            ]
        )
        session.commit()

        first = cluster_articles(session)
        assert len(first) == 1
        count_after_first = session.scalar(select(func.count(Cluster.id)))

        second = cluster_articles(session)
        assert len(second) == 1
        assert session.scalar(select(func.count(Cluster.id))) == count_after_first


class TestConflictDedup:
    def _claims(self, session, seed_source, text_a: str, text_b: str) -> None:
        art1 = _article(session, seed_source, "https://example.com/v1")
        art2 = _article(session, seed_source, "https://example.com/v2")
        shared_evidence = "The Acme Aerospace targeting campaign exploiting Edge Gateway against contractors observed broadly"
        session.add_all(
            [
                Claim(
                    article_id=art1.id,
                    claim_type="attribution",
                    claim_text=text_a,
                    evidence_text=shared_evidence + " APT28",
                ),
                Claim(
                    article_id=art2.id,
                    claim_type="attribution",
                    claim_text=text_b,
                    evidence_text=shared_evidence + " APT29",
                ),
            ]
        )
        session.commit()

    def test_second_run_creates_no_duplicates(self, session, seed_source):
        self._claims(session, seed_source, "attributed to APT28", "attributed to APT29")
        first = detect_conflicts(session)
        assert len(first) == 1
        assert detect_conflicts(session) == []
        assert session.scalar(select(func.count(Conflict.id))) == 1

    def test_shared_stopword_does_not_suppress_conflict(self, session, seed_source):
        """Both claims starting with 'The' must not read as same-attribution."""
        self._claims(
            session,
            seed_source,
            "The campaign was attributed to APT28",
            "The campaign was attributed to APT29",
        )
        new = detect_conflicts(session)
        assert any(c.conflict_type == "attribution_disagreement" for c in new)

    def test_same_actor_still_treated_as_agreement(self, session, seed_source):
        self._claims(session, seed_source, "attributed to APT28", "also attributed to APT28")
        assert detect_conflicts(session) == []


# ------------------------- migrations / indexes -------------------------


class TestMigrations:
    def test_run_migrations_idempotent_and_indexes_present(self):
        from sqlalchemy import inspect

        from scry.db import get_engine

        run_migrations()
        run_migrations()  # second pass must be a no-op, not an error
        indexes = inspect(get_engine())
        assert "ix_observables_risk_score" in {i["name"] for i in indexes.get_indexes("observables")}
        assert "ix_observables_status" in {i["name"] for i in indexes.get_indexes("observables")}
        assert "ix_cves_kev" in {i["name"] for i in indexes.get_indexes("cves")}
        assert "ix_articles_ingested_at" in {i["name"] for i in indexes.get_indexes("articles")}
        assert "ix_source_fetches_fetched_at" in {i["name"] for i in indexes.get_indexes("source_fetches")}


# ------------------------- alias resolution / benign infra -------------------------


class TestAliasResolution:
    def test_non_aliased_types_pass_through_unchanged(self):
        # "Cozy Bear" is an APT29 (threat_actor) alias; as a tool name it must
        # NOT resolve through an alias table.
        assert resolve_canonical("Cozy Bear", "tool") == ("Cozy Bear", [])
        # "ALPHV" is a BlackCat (malware_family) alias; campaigns pass through.
        assert resolve_canonical("ALPHV", "campaign") == ("ALPHV", [])

    def test_aliased_types_still_resolve(self):
        assert resolve_canonical("Cozy Bear", "threat_actor")[0] == "APT29"
        assert resolve_canonical("ALPHV", "malware_family")[0] == "BlackCat"


class TestBenignInfraSuffix:
    def test_lookalike_domain_not_tagged_benign(self):
        iocs = IOCExtractor().extract("Exfil to notamazonaws.com and cdn.amazonaws.com observed.")
        by_value = {i.normalized_value: i for i in iocs}
        assert "benign-shared-infrastructure" not in by_value["notamazonaws.com"].tags
        assert "benign-shared-infrastructure" in by_value["cdn.amazonaws.com"].tags


# ------------------------- AI prompt budgeting -------------------------


class _FakeLocalProvider:
    """Stand-in for LocalLlamaProvider — records the messages it receives."""

    name = "local"

    def __init__(self, model_path: Path):
        self._path = model_path
        self.last_messages: list[dict] | None = None

    @property
    def model_path(self) -> Path:
        return self._path

    def is_available(self) -> bool:
        return True

    async def chat_stream(self, messages, model="", system="", max_tokens=512):
        self.last_messages = messages
        yield ChatChunk(text="ok", done=True, tokens_in=10, tokens_out=5)


def _big_history(pairs: int = 8) -> list[dict[str, str]]:
    history: list[dict[str, str]] = []
    for i in range(pairs):
        history.append({"role": "user", "content": f"u{i} " + "x" * 3000})
        history.append({"role": "assistant", "content": f"a{i} " + "y" * 3000})
    return history


class TestPromptBudgeting:
    def test_trim_history_drops_oldest_pairs_first(self):
        trimmed = ai_mod._trim_history(_big_history(), char_budget=4500)
        assert sum(len(m["content"]) for m in trimmed) <= 4500
        assert trimmed[-1]["content"].startswith("a7")  # newest exchange survives
        assert trimmed[0]["role"] == "user"  # alternation preserved
        assert not any(m["content"].startswith("u0") for m in trimmed)

    def test_cap_sources_truncates_and_renumbers(self):
        sources = [
            {"n": i + 1, "type": "article", "title": f"t{i}", "snippet": "s" * 2000, "link": ""}
            for i in range(8)
        ]
        capped = ai_mod._cap_sources(sources, char_budget=2500)
        assert 0 < len(capped) < len(sources)
        assert [s["n"] for s in capped] == list(range(1, len(capped) + 1))
        assert all(len(s["snippet"]) <= ai_mod._SNIPPET_CHAR_CAP + 1 for s in capped)

    async def test_huge_history_stays_within_context_budget(self, session, monkeypatch, tmp_path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")
        provider = _FakeLocalProvider(model_file)
        monkeypatch.setattr(ai_mod, "_resolve_provider", lambda s: provider)
        monkeypatch.setenv("CTI_ENABLE_AI_SEARCH", "true")

        result = await ai_mod.answer_question(session, "what ransomware activity?", history=_big_history())
        assert result["answer"] == "ok"
        total_chars = sum(len(m["content"]) for m in provider.last_messages)
        assert total_chars <= ai_mod._PROMPT_TOKEN_BUDGET * ai_mod._CHARS_PER_TOKEN
        # messages[-1] is the new question; [-3:-1] is the newest kept pair
        assert provider.last_messages[-3]["content"].startswith("u7")
        assert provider.last_messages[-2]["content"].startswith("a7")
