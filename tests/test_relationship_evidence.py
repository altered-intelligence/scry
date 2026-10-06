"""Relationship evidence cap.

The extractor used to store the whole surrounding "sentence" as relationship
evidence; punctuation-free inputs (pasted IOC sheets) turned that into
hundreds of KB copied onto every relationship row. Covers the window
function, bounded evidence from the extractor and the pipeline sink, the
repair routine (idempotent + dry-run), the CLI command, and the startup
migration hook.
"""

from __future__ import annotations

from sqlalchemy import select
from typer.testing import CliRunner

from scry.cli import app as cli_app
from scry.extraction.entity_extractor import EntityExtractor
from scry.extraction.ioc_extractor import IOCExtractor
from scry.extraction.relationship_extractor import (
    MAX_EVIDENCE_CHARS,
    RelationshipExtractor,
    evidence_window,
)
from scry.migrations import run_migrations
from scry.models import Article, Entity, Observable, Relationship
from scry.pipeline import CTIPipeline
from scry.retention import truncate_relationship_evidence

runner = CliRunner()


# ------------------------- evidence_window -------------------------


class TestEvidenceWindow:
    def test_short_text_verbatim(self):
        text = "  APT29 uses Cobalt Strike to maintain persistence.  "
        assert evidence_window(text, [["APT29"], ["Cobalt Strike"]]) == text.strip()

    def test_both_endpoints_kept_in_one_window(self):
        filler = "x" * 5000
        text = f"{filler} Lumma stealer beacons to {'y' * 150} evil-c2.example.net daily {filler}"
        out = evidence_window(text, [["Lumma"], ["evil-c2.example.net"]])
        assert len(out) <= MAX_EVIDENCE_CHARS
        assert "lumma" in out.lower() and "evil-c2.example.net" in out
        assert out.startswith("...") and out.endswith("...")

    def test_far_apart_endpoints_become_two_fragments(self):
        text = "Lumma dropper noted " + "z" * 20000 + " far-away.example.net end"
        out = evidence_window(text, [["Lumma"], ["far-away.example.net"]])
        assert len(out) <= MAX_EVIDENCE_CHARS
        assert out.startswith("Lumma")  # no leading marker at offset 0
        assert "far-away.example.net" in out and " ... " in out
        assert not out.endswith("...")  # the text's own end survives

    def test_closest_pair_is_chosen_not_first_occurrence(self):
        # The entity appears in a header far from the IOC and again right next to it.
        header = "Lumma stealer infrastructure"
        text = header + " " + "q" * 10000 + " - c2-0001.example.net c2 host linked to Lumma " + "q" * 10000
        out = evidence_window(text, [["Lumma"], ["c2-0001.example.net"]])
        assert len(out) <= MAX_EVIDENCE_CHARS
        assert "c2-0001.example.net c2 host linked to Lumma" in out
        assert " ... " not in out  # one tight window, not two fragments

    def test_case_insensitive_and_alias_forms(self):
        text = "w" * 1000 + " LUMMAC2 panel hxxp://bad.example[.]com " + "w" * 1000
        out = evidence_window(
            text, [["Lumma", "LummaC2"], ["http://bad.example.com", "hxxp://bad.example[.]com"]]
        )
        assert "LUMMAC2" in out and "bad.example[.]com" in out
        assert len(out) <= MAX_EVIDENCE_CHARS

    def test_unknown_endpoints_fall_back_to_head(self):
        text = "a" * 2000
        out = evidence_window(text, [["nope"], ["missing"]])
        assert out.startswith("aaa") and out.endswith("...")
        assert len(out) <= MAX_EVIDENCE_CHARS

    def test_single_endpoint_centres_on_it(self):
        text = "m" * 3000 + " only-this.example.net " + "m" * 3000
        out = evidence_window(text, [["absent"], ["only-this.example.net"]])
        assert "only-this.example.net" in out and len(out) <= MAX_EVIDENCE_CHARS

    def test_custom_cap_is_respected(self):
        text = "Lumma " + "b" * 500 + " c2.example.net"
        out = evidence_window(text, [["Lumma"], ["c2.example.net"]], max_chars=120)
        assert len(out) <= 120 and "Lumma" in out and "c2.example.net" in out


# ------------------------- extractor + pipeline -------------------------


def _ioc_sheet(lines: int = 300, mention_entity_per_line: bool = True) -> str:
    """A punctuation-free IOC dump: one giant 'sentence' for the splitter."""
    head = ["Lumma stealer infrastructure collected this week"]
    suffix = " linked to Lumma" if mention_entity_per_line else ""
    return "\n".join(head + [f"- c2-{i:04d}.example.net — c2 host{suffix}" for i in range(lines)])


class TestExtractorBoundsEvidence:
    def _rels(self, text: str):
        iocs = IOCExtractor().extract(text)
        entities = EntityExtractor().extract(text)
        return RelationshipExtractor().extract(text, iocs=iocs, entities=entities)

    def test_punctuation_free_dump_yields_bounded_evidence(self):
        rels = self._rels(_ioc_sheet())
        domain_rels = [r for r in rels if r.target_type == "domain"]
        assert len(domain_rels) >= 300
        assert all(len(r.evidence_text) <= MAX_EVIDENCE_CHARS for r in rels)
        for r in domain_rels[:25]:
            assert "lumma" in r.evidence_text.lower()
            assert r.target_value in r.evidence_text.lower()

    def test_entity_only_in_header_links_only_nearby_rows(self):
        """A header mention must not vouch for rows far below it (roundup leak)."""
        rels = [r for r in self._rels(_ioc_sheet(mention_entity_per_line=False)) if r.target_type == "domain"]
        assert rels, "rows right under the header are still linked"
        assert not [r for r in rels if r.target_value.endswith("0250.example.net")]
        for r in rels:
            assert len(r.evidence_text) <= MAX_EVIDENCE_CHARS
            assert "lumma" in r.evidence_text.lower() and r.target_value in r.evidence_text.lower()

    def test_prose_evidence_unchanged(self):
        text = "APT29 uses Cobalt Strike to maintain persistence."
        rels = self._rels(text)
        assert rels and all(r.evidence_text == text for r in rels)

    def test_pipeline_persists_bounded_evidence(self, session, seed_source):
        art = Article(
            source_id=seed_source.id,
            title="sheet",
            url="https://example.com/sheet",
            extracted_text=_ioc_sheet(120),
        )
        session.add(art)
        session.commit()
        CTIPipeline(session).process_article(art)
        rows = session.scalars(select(Relationship).where(Relationship.article_id == art.id)).all()
        assert rows
        assert max(len(r.evidence_text) for r in rows) <= MAX_EVIDENCE_CHARS


# ------------------------- repair of stored rows -------------------------


def _seed_oversized(session, *, n: int = 3, bulk: int = 20_000):
    ent = Entity(type="malware_family", canonical_name="Lumma", aliases=["LummaC2"])
    session.add(ent)
    session.flush()
    rels = []
    for i in range(n):
        value = f"c2-{i}.example.net"
        ob = Observable(type="domain", value=value, normalized_value=value)
        session.add(ob)
        session.flush()
        evidence = "LummaC2 panel list " + "x" * bulk + f" - {value} — c2 host " + "x" * bulk
        rel = Relationship(
            source_type="malware_family",
            source_id=ent.id,
            target_type="domain",
            target_id=ob.id,
            relationship_type="communicates_with",
            evidence_text=evidence,
            extraction_method="cooccurrence",
        )
        session.add(rel)
        rels.append(rel)
    short = Relationship(
        source_type="malware_family",
        source_id=ent.id,
        target_type="domain",
        target_id=rels[0].target_id,
        relationship_type="associated_with",
        evidence_text="Lumma talks to c2-0.example.net",
        extraction_method="cooccurrence",
    )
    session.add(short)
    session.commit()
    return rels, short


class TestRepair:
    def test_trims_oversized_rows_keeping_both_endpoints(self, session):
        rels, short = _seed_oversized(session)
        res = truncate_relationship_evidence(session)
        session.commit()
        assert res["candidates"] == 3 and res["truncated"] == 3
        assert res["bytes_reclaimed"] > 3 * 39_000
        session.expire_all()
        for rel in rels:
            fresh = session.get(Relationship, rel.id)
            assert len(fresh.evidence_text) <= MAX_EVIDENCE_CHARS
            assert "lumma" in fresh.evidence_text.lower()
            target = session.get(Observable, rel.target_id).normalized_value
            assert target in fresh.evidence_text
        assert session.get(Relationship, short.id).evidence_text == "Lumma talks to c2-0.example.net"

    def test_idempotent(self, session):
        _seed_oversized(session)
        truncate_relationship_evidence(session)
        session.commit()
        again = truncate_relationship_evidence(session)
        assert again["candidates"] == 0 and again["truncated"] == 0 and again["bytes_reclaimed"] == 0

    def test_dry_run_writes_nothing(self, session):
        rels, _ = _seed_oversized(session, n=2)
        res = truncate_relationship_evidence(session, dry_run=True)
        session.commit()
        assert res["candidates"] == 2 and res["truncated"] == 0
        assert res["bytes_reclaimed"] > 0
        session.expire_all()
        assert len(session.get(Relationship, rels[0].id).evidence_text) > MAX_EVIDENCE_CHARS

    def test_startup_migration_repairs_rows(self, session):
        rels, _ = _seed_oversized(session, n=2)
        run_migrations()
        session.expire_all()
        assert all(len(session.get(Relationship, r.id).evidence_text) <= MAX_EVIDENCE_CHARS for r in rels)


class TestCLI:
    def test_dry_run_flag(self, session):
        rels, _ = _seed_oversized(session, n=2)
        r = runner.invoke(cli_app, ["prune-evidence", "--dry-run"])
        assert r.exit_code == 0, r.output
        assert "DRY RUN" in r.output and "Would trim" in r.output
        session.expire_all()
        assert len(session.get(Relationship, rels[0].id).evidence_text) > MAX_EVIDENCE_CHARS

    def test_real_run_trims_and_vacuums(self, session):
        rels, _ = _seed_oversized(session, n=2)
        r = runner.invoke(cli_app, ["prune-evidence"])
        assert r.exit_code == 0, r.output
        assert "Trimmed" in r.output and "VACUUM done" in r.output
        session.expire_all()
        assert all(len(session.get(Relationship, x.id).evidence_text) <= MAX_EVIDENCE_CHARS for x in rels)

    def test_no_vacuum_and_custom_cap(self, session):
        rels, _ = _seed_oversized(session, n=1)
        r = runner.invoke(cli_app, ["prune-evidence", "--max-chars", "150", "--no-vacuum"])
        assert r.exit_code == 0, r.output
        assert "VACUUM" not in r.output
        session.expire_all()
        assert len(session.get(Relationship, rels[0].id).evidence_text) <= 150
