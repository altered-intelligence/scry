"""Accuracy regressions from the 2026-10 product review.

"Telerik UI for ASP.NET AJAX" became the domain observable asp.net with risk
99, Cl0p tags and a high-risk alert; every CVE in a weekly roundup inherited
the roundup's Cl0p tag. These tests pin the fixes: product names are not
domains, attribution needs local evidence, article-wide topics barely move
an item's risk, unverified indicators stay below block level, and every
score carries its explanation.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from scry.extraction.entity_extractor import EntityExtractor
from scry.extraction.ioc_extractor import IOCExtractor
from scry.extraction.relationship_extractor import RelationshipExtractor
from scry.models import AnalystReview, Article, Claim, Observable, ObservableMention, Relationship
from scry.pipeline import RETRACTED_TAG, CTIPipeline, reprocess_articles
from scry.scoring.risk import UNVERIFIED_RISK_CEILING, RiskInputs, RiskScorer

ROUNDUP = (
    "Weekly vulnerability roundup. The Cl0p ransomware gang is exploiting a zero-day in file transfer "
    "software and listing victims on its leak site. "
    + "Unrelated filler about patch management practices and asset inventories. " * 4
    + "Separately, Progress shipped fixes for Telerik UI for ASP.NET AJAX (CVE-2019-18935), a flaw "
    "actively exploited in the wild. "
    + "More filler on Patch Tuesday scheduling and change windows for Microsoft Windows. " * 4
    + "Finally, Foo Corp patched CVE-2026-11111 in its router firmware; no exploitation is known."
)


def _ioc(text: str, value: str):
    return next((c for c in IOCExtractor().extract(text) if c.normalized_value == value), None)


# ---------------------------------------------------------------- extraction


class TestProductNamesAreNotDomains:
    @pytest.mark.parametrize("name", ["ASP.NET", "VB.NET", "ADO.NET", "Microsoft.NET", "asp.net"])
    def test_dotnet_product_names_are_dropped(self, name):
        assert _ioc(f"Telerik UI for {name} AJAX is affected.", name.lower()) is None

    def test_real_lowercase_net_domain_still_extracted(self):
        assert _ioc("The loader beacons to update-check.net every hour.", "update-check.net") is not None

    def test_defanged_net_domain_still_extracted(self):
        assert _ioc("C2: evil-host[.]net", "evil-host.net") is not None

    def test_policy_denylist_extends_the_builtin_list(self, monkeypatch):
        import scry.extraction.ioc_extractor as mod

        monkeypatch.setattr(mod, "load_policies", lambda: {"software_name_denylist": ["socket.io"]})
        assert not [c for c in mod.IOCExtractor().extract("Built with socket.io today") if c.type == "domain"]

    def test_file_extension_tld_is_flagged_not_dropped(self):
        c = _ioc("See README.md and setup.py for build steps.", "readme.md")
        assert c is not None and "possible-filename" in c.tags
        assert c.false_positive_risk >= 0.6 and c.maliciousness_confidence <= 30


class TestLocalContext:
    def test_malicious_wording_next_to_the_indicator_raises_confidence(self):
        c = _ioc("The implant beacons to c2-relay.com over HTTPS.", "c2-relay.com")
        assert "malicious-context" in c.tags and c.maliciousness_confidence >= 70

    def test_indicator_text_never_supplies_its_own_context(self):
        c = _ioc(
            "Read it at https://news.example.org/ransomware-c2-payload-analysis today.", "news.example.org"
        )
        assert "malicious-context" not in c.tags

    def test_victim_domain_is_not_attacker_infrastructure(self):
        c = _ioc("ShinyHunters broke into the FBIjobs.gov portal and stole applicant data.", "fbijobs.gov")
        assert "victim-context" in c.tags and "malicious-context" not in c.tags
        assert c.maliciousness_confidence <= 30

    def test_citation_link_is_a_reference(self):
        text = "Source cluster (related IOCs, reporting): https://tracker.example.io/cluster/abc Aggregated by X."
        c = _ioc(text, "tracker.example.io")
        assert "reference-context" in c.tags and c.maliciousness_confidence <= 30

    def test_reference_host_from_policy(self):
        c = _ioc("Malicious sample on virustotal.com was flagged.", "virustotal.com")
        assert "reference-context" in c.tags


class TestAmbiguousEntityNames:
    @pytest.mark.parametrize(
        "text",
        ["Press play to watch the replay.", "A beacon of hope for defenders.", "Users play games at night."],
    )
    def test_common_words_are_not_malware(self, text):
        assert not EntityExtractor().extract(text)

    def test_capitalised_name_with_threat_context_matches(self):
        names = {e.canonical_name for e in EntityExtractor().extract("The Play ransomware gang hit a city.")}
        assert "Play" in names

    def test_capitalised_name_without_threat_context_does_not_match(self):
        assert not EntityExtractor().extract("Play is a word that starts this sentence.")


class TestRelationshipsNeedLocalEvidence:
    def _rels(self, text):
        iocs = IOCExtractor().extract(text)
        ents = EntityExtractor().extract(text)
        return RelationshipExtractor().extract(text, iocs=iocs, entities=ents)

    def test_actor_and_cve_far_apart_in_one_sentence_are_not_linked(self):
        text = (
            "Cl0p ransomware listed victims " + "and more words " * 20 + "while CVE-2026-11111 was patched."
        )
        assert not [r for r in self._rels(text) if r.target_type == "cve"]

    def test_actor_near_cve_without_exploit_verb_is_not_linked(self):
        text = "Cl0p ransomware and CVE-2026-11111 both appeared in the news."
        assert not [r for r in self._rels(text) if r.target_type == "cve"]

    def test_actor_exploiting_cve_nearby_is_linked(self):
        text = "Cl0p ransomware exploited CVE-2023-34362 in MOVEit Transfer."
        rels = [r for r in self._rels(text) if r.target_type == "cve"]
        assert rels and rels[0].relationship_type == "exploits"


# ---------------------------------------------------------------- scoring


def _inputs(**over):
    base = dict(
        maliciousness_confidence=50,
        source_confidence=80,
        recency_days=1,
        independent_sources=1,
        attached_topics={"ransomware", "exploited-in-the-wild", "microsoft"},
        benign_context_flags=[],
        enrichment={},
        local_topics=set(),
        ioc_type="domain",
    )
    base.update(over)
    return RiskInputs(**base)


class TestRiskScoring:
    def test_article_wide_topics_add_little(self):
        risk = RiskScorer().score(_inputs())
        names = dict(risk.contributors)
        assert "article_topic:ransomware" in names and names["article_topic:ransomware"] == 5
        assert "topic:ransomware" not in names

    def test_unverified_indicator_is_capped_below_block(self):
        risk = RiskScorer().score(_inputs(local_topics={"ransomware", "exploited-in-the-wild", "microsoft"}))
        assert risk.score == UNVERIFIED_RISK_CEILING
        assert risk.actionability == "high_priority_hunt"
        assert "unverified_ceiling" in dict(risk.contributors)

    @pytest.mark.parametrize(
        "over",
        [
            {"maliciousness_confidence": 70},
            {"independent_sources": 2},
            {"corroborating_flags": ["virustotal_escalated"]},
        ],
    )
    def test_evidence_lifts_the_cap(self, over):
        risk = RiskScorer().score(_inputs(local_topics={"ransomware", "exploited-in-the-wild"}, **over))
        assert risk.score > UNVERIFIED_RISK_CEILING

    def test_cves_are_not_capped(self):
        risk = RiskScorer().score(
            _inputs(ioc_type="cve", enrichment={"kev": True}, local_topics={"ransomware"})
        )
        assert risk.score > UNVERIFIED_RISK_CEILING

    def test_legacy_callers_keep_full_topic_bumps(self):
        risk = RiskScorer().score(_inputs(local_topics=None, ioc_type=None))
        assert dict(risk.contributors)["topic:ransomware"] == 20


# ---------------------------------------------------------------- pipeline


def _article(session, source, text, url="https://example.com/roundup"):
    art = Article(
        source_id=source.id,
        title="Weekly roundup",
        url=url,
        extracted_text=text,
        published_at=datetime.now(UTC),
        ingested_at=datetime.now(UTC),
        source_confidence=80,
    )
    session.add(art)
    session.commit()
    return art


def _ob(session, value):
    return session.scalar(select(Observable).where(Observable.normalized_value == value))


class TestRoundupPipeline:
    def test_aspnet_is_never_an_observable(self, session, seed_source):
        CTIPipeline(session).process_article(_article(session, seed_source, ROUNDUP))
        assert _ob(session, "asp.net") is None

    def test_cves_far_from_the_actor_do_not_get_its_tags(self, session, seed_source):
        CTIPipeline(session).process_article(_article(session, seed_source, ROUNDUP))
        cve = _ob(session, "CVE-2026-11111")
        assert cve is not None
        assert not [t for t in cve.tags if "cl0p" in t]
        assert "source:test-vendor-blog" in cve.tags  # provenance still applies everywhere

    def test_no_actor_exploits_cve_relationship_from_a_roundup(self, session, seed_source):
        CTIPipeline(session).process_article(_article(session, seed_source, ROUNDUP))
        assert not session.scalars(select(Relationship).where(Relationship.target_type == "cve")).all()

    def test_score_breakdown_is_stored(self, session, seed_source):
        CTIPipeline(session).process_article(_article(session, seed_source, ROUNDUP))
        cve = _ob(session, "CVE-2019-18935")
        breakdown = cve.enrichment["risk_breakdown"]
        assert breakdown["score"] == cve.risk_score and breakdown["contributors"]

    def test_victim_domain_gets_no_actor_tag(self, session, seed_source):
        text = "Cl0p ransomware operators breached the acme-corp.com portal and stole customer data."
        CTIPipeline(session).process_article(_article(session, seed_source, text))
        ob = _ob(session, "acme-corp.com")
        assert "victim-context" in ob.tags and not [t for t in ob.tags if "cl0p" in t]


class TestReprocess:
    def test_retracts_what_the_extractor_now_rejects_and_drops_stale_tags(self, session, seed_source):
        art = _article(session, seed_source, ROUNDUP)
        CTIPipeline(session).process_article(art)
        # Simulate rows written by the old extractor.
        stale = Observable(
            type="domain", value="ASP.NET", normalized_value="asp.net", validation_status="valid",
            extraction_confidence=75, maliciousness_confidence=50, false_positive_risk=0.0,
            risk_score=99, actionability="urgent_review", status="active", ttl_days=30,
            enrichment={}, tags=["malware:cl0p"], scoring_model_version="0.1",
        )  # fmt: skip
        session.add(stale)
        session.flush()
        session.add(ObservableMention(observable_id=stale.id, article_id=art.id, extraction_method="regex"))
        cve = _ob(session, "CVE-2026-11111")
        cve.tags = [*cve.tags, "malware:cl0p", "actor:cl0p"]
        session.commit()

        res = reprocess_articles(session, [art.id])
        session.expire_all()
        assert res["observables_retracted"] == 1
        stale = _ob(session, "asp.net")
        assert stale.status == "false_positive" and stale.risk_score == 0 and RETRACTED_TAG in stale.tags
        assert not [t for t in _ob(session, "CVE-2026-11111").tags if "cl0p" in t]

    def test_keeps_imported_mentions(self, session, seed_source):
        art = _article(session, seed_source, "Nothing extractable here.")
        alias = Observable(
            type="alias", value="Big Fish", normalized_value="big fish", validation_status="valid",
            extraction_confidence=90, maliciousness_confidence=50, false_positive_risk=0.0,
            risk_score=40, actionability="monitor", status="active", ttl_days=0,
            enrichment={}, tags=[], scoring_model_version="0.1",
        )  # fmt: skip
        session.add(alias)
        session.flush()
        session.add(
            ObservableMention(observable_id=alias.id, article_id=art.id, extraction_method="manual_import")
        )
        session.commit()
        reprocess_articles(session, [art.id])
        session.expire_all()
        assert _ob(session, "big fish").status == "active"
        assert session.scalars(
            select(ObservableMention).where(ObservableMention.observable_id == alias.id)
        ).all()

    def test_analyst_decisions_survive(self, session, seed_source):
        text = "Microsoft confirmed CVE-2026-22222 is actively exploited in the wild by attackers."
        art = _article(session, seed_source, text)
        CTIPipeline(session).process_article(art)
        review = session.scalar(select(AnalystReview).where(AnalystReview.item_type == "claim"))
        assert review is not None, "fixture text must produce a reviewable claim"
        review.status, review.disposition = "closed", "true_positive"
        session.commit()

        reprocess_articles(session, [art.id])
        session.expire_all()
        assert not session.scalars(select(AnalystReview).where(AnalystReview.status == "open")).all()
        review = session.get(AnalystReview, review.id)
        claim = session.get(Claim, review.item_id)
        assert claim is not None and claim.review_status == "true_positive" and not claim.needs_review


class TestBenignSignals:
    def test_vendor_clean_verdict_counts_against_risk(self):
        from scry.pipeline import vendor_clean_flags

        clean = {"virustotal": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 61}}}
        dirty = {"virustotal": {"last_analysis_stats": {"malicious": 12, "harmless": 50}}}
        assert vendor_clean_flags(clean) == ["vendor-clean:virustotal"]
        assert vendor_clean_flags(dirty) == []
        assert vendor_clean_flags({"greynoise": {"classification": "benign"}}) == ["vendor-clean:greynoise"]

    def test_reference_and_victim_tags_lower_risk(self, session, seed_source):
        text = "Attackers breached the shop-example.com portal and stole card data."
        CTIPipeline(session).process_article(_article(session, seed_source, text))
        ob = _ob(session, "shop-example.com")
        assert any(
            name.startswith("benign_context:victim-context")
            for name, _ in ob.enrichment["risk_breakdown"]["contributors"]
        )
