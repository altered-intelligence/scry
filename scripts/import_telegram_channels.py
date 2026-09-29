#!/usr/bin/env python3
"""Import telegram channels into the telegram_channels table."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scry.db import get_engine, session_scope
from scry.models import Base, TelegramChannel


def main(path: str) -> None:
    src = Path(path)
    with src.open(encoding="utf-8") as f:
        channels: list[dict] = json.load(f)

    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    inserted = 0
    updated = 0
    with session_scope() as session:
        for ch in channels:
            username = ch.get("username", "").strip()
            if not username:
                continue
            existing = session.execute(
                __import__("sqlalchemy").text("SELECT id FROM telegram_channels WHERE username = :u"),
                {"u": username},
            ).fetchone()
            if existing:
                session.execute(
                    __import__("sqlalchemy").text(
                        "UPDATE telegram_channels SET name=:n, url=:url WHERE username=:u"
                    ),
                    {
                        "n": ch.get("name") or username,
                        "url": ch.get("url") or f"https://t.me/{username}",
                        "u": username,
                    },
                )
                updated += 1
            else:
                session.add(
                    TelegramChannel(
                        username=username,
                        name=ch.get("name") or username,
                        description=ch.get("description") or None,
                        url=ch.get("url") or f"https://t.me/{username}",
                    )
                )
                inserted += 1
        session.commit()

    print(f"[OK] Inserted {inserted}, updated {updated} telegram channels")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_telegram_channels.py <channels.json>")
        sys.exit(1)
    main(sys.argv[1])
