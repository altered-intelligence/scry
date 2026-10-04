"""Ransomware victim feed import.

Loads exported ransomware-victim listings (JSON, JSON Lines, or CSV, as
provided by feed trackers such as ransomware.live or Dark Web Informer) into
``ransomware_feed_items`` so they appear under Intel Feeds → Ransomware Feeds.

This is a FILE import: it reads a file you exported yourself and never
fetches anything. Stored claim/post URLs (often ``.onion`` leak-site links)
are kept as inert text; nothing here — or in the UI — requests them. Respect
the provider's terms: use their own export or API within its limits, keep the
data local, and attribute the source (every item is tagged ``source:<name>``).

Field names vary between providers, so each logical field accepts several
aliases (case-insensitive). Rows without a victim name or a group are skipped.
Items are de-duplicated on (group, victim) — the model's ``post_hash`` — so
re-importing an export updates existing rows instead of duplicating them.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dateutil import parser as dt_parser
from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.logging import get_logger
from scry.models import RansomwareFeedItem

logger = get_logger("ingest.ransomware_feed")

# logical field -> accepted keys (lowercased, first match wins)
ALIASES: dict[str, tuple[str, ...]] = {
    "victim": ("victim", "victim_name", "post_title", "title", "name", "company", "organization", "org"),
    "group": ("group", "group_name", "gang", "actor", "threat_actor", "ransomware_group"),
    "discovered": (
        "discovered",
        "detected",
        "found",
        "first_seen",
        "timestamp",
        "date",
        "created",
        "created_at",
    ),
    "published": ("published", "post_date", "published_at", "attack_date", "leak_date"),
    "country": ("country", "country_code", "victim_country", "cc"),
    "sector": ("sector", "industry", "activity", "victim_industry"),
    "website": ("website", "domain", "victim_website", "victim_domain", "site"),
    "description": ("description", "summary", "details", "notes"),
    "claim_url": ("claim_url", "claim", "onion", "onion_url", "leak_url", "leaksite_url"),
    "post_url": ("post_url", "url", "link", "permalink", "reference"),
    "severity": ("severity", "risk", "priority"),
}

# severity label -> risk_score (0-100)
SEVERITY_RISK = {"critical": 90.0, "high": 75.0, "medium": 50.0, "low": 25.0}

_LIST_KEYS = ("data", "incidents", "results", "items", "records", "victims", "posts", "entries")
_BATCH = 500

# Country name -> ISO 3166-1 alpha-2 (the model stores a 2-letter code).
_COUNTRIES = (
    "AF Afghanistan|AX Åland Islands|AL Albania|DZ Algeria|AD Andorra|AO Angola|AI Anguilla|"
    "AG Antigua & Barbuda|AR Argentina|AM Armenia|AW Aruba|AU Australia|AT Austria|AZ Azerbaijan|"
    "BS Bahamas|BH Bahrain|BD Bangladesh|BB Barbados|BY Belarus|BE Belgium|BZ Belize|BM Bermuda|"
    "BT Bhutan|BO Bolivia|BA Bosnia & Herzegovina|BW Botswana|BR Brazil|VG British Virgin Islands|"
    "BG Bulgaria|BF Burkina Faso|KH Cambodia|CM Cameroon|CA Canada|KY Cayman Islands|TD Chad|"
    "CL Chile|CN China|CO Colombia|CG Congo - Brazzaville|CD Congo - Kinshasa|CR Costa Rica|"
    "CI Côte d'Ivoire|HR Croatia|CU Cuba|CW Curaçao|CY Cyprus|CZ Czechia|DK Denmark|DJ Djibouti|"
    "DM Dominica|DO Dominican Republic|EC Ecuador|EG Egypt|SV El Salvador|EE Estonia|ET Ethiopia|"
    "FO Faroe Islands|FJ Fiji|FI Finland|FR France|GA Gabon|GM Gambia|GE Georgia|DE Germany|GH Ghana|"
    "GR Greece|GT Guatemala|GN Guinea|GY Guyana|HT Haiti|HN Honduras|HK Hong Kong|HU Hungary|"
    "IS Iceland|IN India|ID Indonesia|IR Iran|IQ Iraq|IE Ireland|IL Israel|IT Italy|JM Jamaica|"
    "JP Japan|JE Jersey|JO Jordan|KZ Kazakhstan|KE Kenya|KI Kiribati|KW Kuwait|LA Laos|LV Latvia|"
    "LB Lebanon|LS Lesotho|LY Libya|LT Lithuania|LU Luxembourg|MO Macao|MG Madagascar|MY Malaysia|"
    "MV Maldives|ML Mali|MT Malta|MQ Martinique|MR Mauritania|MU Mauritius|YT Mayotte|MX Mexico|"
    "MD Moldova|MC Monaco|MN Mongolia|ME Montenegro|MS Montserrat|MA Morocco|MZ Mozambique|"
    "MM Myanmar|NA Namibia|NP Nepal|NL Netherlands|NZ New Zealand|NI Nicaragua|NE Niger|NG Nigeria|"
    "MK North Macedonia|NO Norway|OM Oman|PK Pakistan|PW Palau|PS Palestine|PA Panama|"
    "PG Papua New Guinea|PY Paraguay|PE Peru|PH Philippines|PL Poland|PT Portugal|PR Puerto Rico|"
    "QA Qatar|RE Réunion|RO Romania|RU Russia|RW Rwanda|WS Samoa|SA Saudi Arabia|SN Senegal|"
    "RS Serbia|SC Seychelles|SG Singapore|SK Slovakia|SI Slovenia|SO Somalia|ZA South Africa|"
    "KR South Korea|ES Spain|LK Sri Lanka|KN St. Kitts & Nevis|LC St. Lucia|VC St. Vincent & Grenadines|"
    "SD Sudan|SJ Svalbard & Jan Mayen|SE Sweden|CH Switzerland|SY Syria|TW Taiwan|TJ Tajikistan|"
    "TZ Tanzania|TH Thailand|TL Timor-Leste|TK Tokelau|TO Tonga|TT Trinidad & Tobago|TN Tunisia|"
    "TR Türkiye|TC Turks & Caicos Islands|TV Tuvalu|UG Uganda|UA Ukraine|AE United Arab Emirates|"
    "GB United Kingdom|US United States|UY Uruguay|UZ Uzbekistan|VU Vanuatu|VA Vatican City|"
    "VE Venezuela|VN Vietnam|YE Yemen|ZM Zambia|ZW Zimbabwe"
)
_NAME_TO_CODE: dict[str, str] = {}
for _entry in _COUNTRIES.split("|"):
    _code, _, _name = _entry.partition(" ")
    _NAME_TO_CODE[re.sub(r"[^a-z0-9]+", "", _name.lower())] = _code
_NAME_TO_CODE.update(
    {
        "usa": "US",
        "unitedstatesofamerica": "US",
        "uk": "GB",
        "greatbritain": "GB",
        "turkey": "TR",
        "burma": "MM",
        "myanmarburma": "MM",
        "czechrepublic": "CZ",
        "ivorycoast": "CI",
        "uae": "AE",
        "southkorea": "KR",
        "republicofkorea": "KR",
        "russianfederation": "RU",
        "vietnam": "VN",
    }
)


def country_code(value: str | None) -> str | None:
    """ISO alpha-2 for a country name/code, or None when unknown."""
    text = (value or "").strip()
    if not text or text in {"?", "-", "N/A", "n/a", "Unknown", "unknown"}:
        return None
    if re.fullmatch(r"[A-Za-z]{2}", text):
        code = text.upper()
        return {"UK": "GB"}.get(code, code)  # "UK" is the common non-ISO spelling
    return _NAME_TO_CODE.get(re.sub(r"[^a-z0-9]+", "", text.lower()))


def _parse_when(value: Any) -> datetime | None:
    if value in (None, "", "N/A"):
        return None
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d{9,13}", str(value).strip()):
            n = float(value)
            return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, UTC)
        dt = dt_parser.parse(str(value))
    except (ValueError, OverflowError, OSError, TypeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _pick(raw: dict[str, Any], field: str) -> Any:
    lowered = {str(k).strip().lower(): v for k, v in raw.items()}
    for key in ALIASES[field]:
        val = lowered.get(key)
        if val not in (None, ""):
            return val
    return None


def _clean(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text[:limit] if text and text.upper() != "N/A" else None


def post_hash(group: str, victim: str) -> str:
    return hashlib.sha256(f"{group.lower()}|{victim.lower()}".encode()).hexdigest()[:64]


def normalize_record(raw: dict[str, Any], *, source: str = "import") -> dict[str, Any] | None:
    """Map one provider row to RansomwareFeedItem fields; None when unusable."""
    victim = _clean(_pick(raw, "victim"), 2048)
    group = _clean(_pick(raw, "group"), 256)
    if not victim or not group:
        return None
    severity = (_clean(_pick(raw, "severity"), 32) or "").lower()
    country_raw = _clean(_pick(raw, "country"), 80)
    tags = ["ransomware", f"source:{source}"]
    if severity in SEVERITY_RISK:
        tags.append(f"severity:{severity}")
    code = country_code(country_raw)
    if country_raw and not code:
        tags.append(f"country:{re.sub(r'[^a-z0-9]+', '-', country_raw.lower()).strip('-')[:40]}")
    discovered = _parse_when(_pick(raw, "discovered"))
    return {
        "post_hash": post_hash(group, victim),
        "post_title": victim,
        "group_name": group,
        "discovered": discovered,
        "published": _parse_when(_pick(raw, "published")),
        "description": _clean(_pick(raw, "description"), 20_000),
        "activity": _clean(_pick(raw, "sector"), 256),
        "victim_website": _clean(_pick(raw, "website"), 512),
        "victim_country": code,
        "post_url": _clean(_pick(raw, "post_url"), 2048),
        "claim_url": _clean(_pick(raw, "claim_url"), 2048),
        "tags": tags,
        "risk_score": SEVERITY_RISK.get(severity),
    }


def load_records(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSON / JSON Lines / CSV export into a list of row dicts."""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig")
    stripped = text.lstrip()
    if p.suffix.lower() == ".csv" or (stripped and stripped[0] not in "[{"):
        return [dict(r) for r in csv.DictReader(io.StringIO(text))]
    try:
        data = json.loads(text)
    except json.JSONDecodeError:  # JSON Lines
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict):
        for key in _LIST_KEYS:
            if isinstance(data.get(key), list):
                return [r for r in data[key] if isinstance(r, dict)]
        return [data]
    return [r for r in data if isinstance(r, dict)]


def import_records(
    session: Session,
    records: list[dict[str, Any]],
    *,
    source: str = "import",
    dry_run: bool = False,
) -> dict[str, int]:
    """Upsert rows into ``ransomware_feed_items``. Returns added/updated/skipped/invalid counts.

    Existing items (same group + victim) only gain data: empty fields are filled,
    tags are merged, and ``discovered`` keeps the earliest sighting.
    """
    counts = {"added": 0, "updated": 0, "skipped": 0, "invalid": 0}
    now = datetime.now(UTC)
    normalized: dict[str, dict[str, Any]] = {}
    for raw in records:
        item = normalize_record(raw, source=source)
        if item is None:
            counts["invalid"] += 1
        elif item["post_hash"] in normalized:
            counts["skipped"] += 1  # duplicate within the file
        else:
            normalized[item["post_hash"]] = item

    hashes = list(normalized)
    for start in range(0, len(hashes), _BATCH):
        chunk = hashes[start : start + _BATCH]
        existing = {
            row.post_hash: row
            for row in session.scalars(
                select(RansomwareFeedItem).where(RansomwareFeedItem.post_hash.in_(chunk))
            )
        }
        for h in chunk:
            item = normalized[h]
            row = existing.get(h)
            if row is None:
                counts["added"] += 1
                if not dry_run:
                    session.add(RansomwareFeedItem(**item, ingested_at=now))
                continue
            changed = False
            for field in (
                "published",
                "description",
                "activity",
                "victim_website",
                "victim_country",
                "post_url",
                "claim_url",
            ):
                if getattr(row, field) in (None, "") and item[field] not in (None, ""):
                    changed = True
                    if not dry_run:
                        setattr(row, field, item[field])
            if item["risk_score"] is not None and row.risk_score is None:
                changed = True
                if not dry_run:
                    row.risk_score = item["risk_score"]
            merged = sorted({*(row.tags or []), *item["tags"]})
            if merged != sorted(row.tags or []):
                changed = True
                if not dry_run:
                    row.tags = merged
            if item["discovered"] and (
                row.discovered is None or _aware(item["discovered"]) < _aware(row.discovered)
            ):
                changed = True
                if not dry_run:
                    row.discovered = item["discovered"]
            counts["updated" if changed else "skipped"] += 1
        if not dry_run:
            session.commit()
    logger.info("ransomware_feed_imported", dry_run=dry_run, source=source, **counts)
    return counts


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
