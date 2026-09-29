"""FastAPI dependencies."""

from __future__ import annotations

import logging
from collections.abc import Generator

from sqlalchemy.orm import Session

from scry.db import session_factory

_log = logging.getLogger(__name__)


def get_session() -> Generator[Session, None, None]:
    factory = session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        _log.exception("db_session_error — rolling back")
        session.rollback()
        raise
    finally:
        session.close()
