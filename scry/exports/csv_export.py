"""CSV exports."""

from __future__ import annotations

import csv
from io import StringIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from scry.models import Observable

# Characters that trigger formula evaluation in Excel / Google Sheets / LibreOffice.
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: object) -> object:
    """Neutralize CSV/spreadsheet formula injection.

    Observable values, tags, and other fields originate from untrusted threat
    feeds. If such a value begins with a formula trigger, a spreadsheet app will
    execute it when an analyst opens the export. Prefix a single quote so the
    cell is treated as literal text. Non-string values pass through unchanged.
    """
    if isinstance(value, str) and value and value[0] in _CSV_FORMULA_TRIGGERS:
        return "'" + value
    return value


def export_observables_csv(session: Session, *, limit: int = 10000) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "type",
            "normalized_value",
            "defanged_value",
            "risk_score",
            "actionability",
            "status",
            "first_seen",
            "last_seen",
            "expiration_date",
            "tags",
        ]
    )
    for o in session.scalars(select(Observable).order_by(Observable.risk_score.desc()).limit(limit)):
        writer.writerow(
            [
                o.id,
                o.type,
                csv_safe(o.normalized_value),
                csv_safe(o.defanged_value or ""),
                o.risk_score,
                o.actionability,
                o.status,
                o.first_seen.isoformat() if o.first_seen else "",
                o.last_seen.isoformat() if o.last_seen else "",
                o.expiration_date.isoformat() if o.expiration_date else "",
                csv_safe("|".join(o.tags or [])),
            ]
        )
    return buf.getvalue()
