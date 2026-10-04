"""Ransomware feed file import (synthetic rows only)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from scry.cli import app as cli_app
from scry.ingestion.ransomware_feed import (
    country_code,
    import_records,
    load_records,
    normalize_record,
    post_hash,
)
from scry.main import app
from scry.models import RansomwareFeedItem

runner = CliRunner()


def _row(**kw):
    base = {
        "victim": "Acme Widgets",
        "group": "examplegroup",
        "date": "2026-10-03T09:05:35Z",
        "country": "United States",
        "sector": "Manufacturing",
        "severity": "HIGH",
    }
    base.update(kw)
    return base


def _count(session):
    return session.scalar(select(func.count(RansomwareFeedItem.id)))


class TestNormalize:
    def test_maps_fields_tags_and_risk(self):
        item = normalize_record(
            _row(
                website="acme.example",
                description="Claimed leak",
                post_url="https://p/1",
                onion="http://abc.onion/x",
            ),
            source="tracker",
        )
        assert item["post_title"] == "Acme Widgets" and item["group_name"] == "examplegroup"
        assert item["victim_country"] == "US" and item["activity"] == "Manufacturing"
        assert item["victim_website"] == "acme.example" and item["claim_url"] == "http://abc.onion/x"
        assert item["risk_score"] == 75.0
        assert set(item["tags"]) == {"ransomware", "source:tracker", "severity:high"}
        assert item["discovered"] == datetime(2026, 10, 3, 9, 5, 35, tzinfo=UTC)
        assert item["post_hash"] == post_hash("examplegroup", "Acme Widgets")

    @pytest.mark.parametrize(
        "alias_row",
        [
            {"victim_name": "V", "gang": "g"},
            {"Title": "V", "Group_Name": "g"},
            {"company": "V", "actor": "g"},
        ],
    )
    def test_field_aliases_are_case_insensitive(self, alias_row):
        item = normalize_record(alias_row)
        assert item["post_title"] == "V" and item["group_name"] == "g"

    @pytest.mark.parametrize("row", [{"group": "g"}, {"victim": "V"}, {"victim": " ", "group": "g"}, {}])
    def test_rows_without_victim_or_group_are_invalid(self, row):
        assert normalize_record(row) is None

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("2026-10-03T09:05:35Z", datetime(2026, 10, 3, 9, 5, 35, tzinfo=UTC)),
            ("10/3/2026, 9:05:35 AM", datetime(2026, 10, 3, 9, 5, 35, tzinfo=UTC)),
            (1791018335, datetime(2026, 10, 3, 9, 5, 35, tzinfo=UTC)),
            (1791018335000, datetime(2026, 10, 3, 9, 5, 35, tzinfo=UTC)),
        ],
    )
    def test_date_formats(self, value, expected):
        assert normalize_record(_row(date=value))["discovered"] == expected

    def test_unparseable_date_is_none_not_a_crash(self):
        assert normalize_record(_row(date="not a date"))["discovered"] is None

    @pytest.mark.parametrize(
        "value,code",
        [
            ("United States", "US"),
            ("usa", "US"),
            ("UK", "GB"),
            ("Türkiye", "TR"),
            ("de", "DE"),
            ("Myanmar (Burma)", "MM"),
            ("?", None),
            ("Atlantis", None),
            ("", None),
        ],
    )
    def test_country_codes(self, value, code):
        assert country_code(value) == code

    def test_unknown_country_keeps_a_tag_instead_of_a_bad_code(self):
        item = normalize_record(_row(country="Atlantis"))
        assert item["victim_country"] is None and "country:atlantis" in item["tags"]

    def test_na_and_oversize_values_are_cleaned(self):
        item = normalize_record(_row(description="N/A", website="x" * 900, victim="V" * 3000))
        assert (
            item["description"] is None
            and len(item["victim_website"]) == 512
            and len(item["post_title"]) == 2048
        )


class TestLoad:
    def test_json_list_object_wrappers_jsonl_and_csv(self, tmp_path):
        rows = [_row(), _row(victim="Beta Corp")]
        (tmp_path / "list.json").write_text(json.dumps(rows))
        (tmp_path / "wrapped.json").write_text(json.dumps({"incidents": rows, "meta": {}}))
        (tmp_path / "lines.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
        (tmp_path / "rows.csv").write_text("victim,group,country\nAcme,g1,France\nBeta,g2,Italy\n")
        assert len(load_records(tmp_path / "list.json")) == 2
        assert len(load_records(tmp_path / "wrapped.json")) == 2
        assert len(load_records(tmp_path / "lines.jsonl")) == 2
        csv_rows = load_records(tmp_path / "rows.csv")
        assert [r["victim"] for r in csv_rows] == ["Acme", "Beta"]

    def test_bom_is_tolerated(self, tmp_path):
        (tmp_path / "bom.csv").write_bytes("﻿victim,group\nA,g\n".encode())
        assert load_records(tmp_path / "bom.csv")[0]["victim"] == "A"


class TestImport:
    def test_adds_dedupes_within_file_and_counts_invalid(self, session):
        counts = import_records(
            session, [_row(), _row(), _row(victim="Beta Corp"), {"group": "x"}], source="t"
        )
        assert counts == {"added": 2, "updated": 0, "skipped": 1, "invalid": 1}
        assert _count(session) == 2

    def test_reimport_is_idempotent(self, session):
        import_records(session, [_row()])
        again = import_records(session, [_row()])
        assert again["added"] == 0 and again["updated"] == 0 and again["skipped"] == 1
        assert _count(session) == 1

    def test_reimport_only_fills_gaps_and_merges_tags(self, session):
        import_records(session, [_row(description="", website="")], source="a")
        later = _row(description="Now with details", website="acme.example", date="2026-10-01T00:00:00Z")
        res = import_records(session, [later], source="b")
        assert res["updated"] == 1
        row = session.scalar(select(RansomwareFeedItem))
        assert row.description == "Now with details" and row.victim_website == "acme.example"
        assert {"source:a", "source:b"} <= set(row.tags)
        assert row.discovered.replace(tzinfo=UTC) == datetime(
            2026, 10, 1, tzinfo=UTC
        )  # earliest sighting wins
        # existing values are never overwritten by a later import
        import_records(session, [_row(description="Different text")], source="b")
        assert session.scalar(select(RansomwareFeedItem)).description == "Now with details"

    def test_dry_run_writes_nothing(self, session):
        counts = import_records(session, [_row(), _row(victim="Beta")], dry_run=True)
        assert counts["added"] == 2 and _count(session) == 0

    def test_large_batches(self, session):
        rows = [_row(victim=f"Victim {i}", group=f"g{i % 7}") for i in range(1200)]
        assert import_records(session, rows)["added"] == 1200
        assert import_records(session, rows)["skipped"] == 1200
        assert _count(session) == 1200


class TestCliAndUi:
    def test_cli_dry_run_then_real_import(self, session, tmp_path):
        f = tmp_path / "feed.json"
        f.write_text(json.dumps([_row(), _row(victim="Beta Corp", country="Germany")]))
        r = runner.invoke(cli_app, ["ingest", "ransomware-feed", str(f), "--source", "tracker", "--dry-run"])
        assert r.exit_code == 0, r.output
        assert "DRY RUN" in r.output and "added 2" in r.output and _count(session) == 0
        r = runner.invoke(cli_app, ["ingest", "ransomware-feed", str(f), "--source", "tracker"])
        assert r.exit_code == 0, r.output
        assert _count(session) == 2
        assert "source:tracker" in session.scalar(select(RansomwareFeedItem)).tags

    def test_cli_rejects_unreadable_file(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json")
        r = runner.invoke(cli_app, ["ingest", "ransomware-feed", str(bad)])
        assert r.exit_code == 1 and "Could not read" in r.output

    def test_imported_items_render_on_the_ransomware_feeds_page(self, session):
        import_records(
            session,
            [_row(onion="http://abc.onion/leak"), _row(victim="Beta Corp", group="othergroup")],
            source="tracker",
        )
        with TestClient(app) as client:
            page = client.get("/ui/intel-feeds/ransomware-feeds")
            assert page.status_code == 200
            assert "Acme Widgets" in page.text and "Beta Corp" in page.text and "othergroup" in page.text
            filtered = client.get("/ui/intel-feeds/ransomware-feeds?group=othergroup")
            assert "Beta Corp" in filtered.text and "Acme Widgets" not in filtered.text
            item_id = session.scalar(
                select(RansomwareFeedItem.id).where(RansomwareFeedItem.post_title == "Acme Widgets")
            )
            detail = client.get(f"/ui/intel-feeds/ransomware-feeds/{item_id}")
            assert detail.status_code == 200 and "abc.onion/leak" in detail.text
            assert 'href="http://abc.onion' not in detail.text  # leak-site URLs stay inert text
