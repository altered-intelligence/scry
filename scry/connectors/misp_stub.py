"""MISP connector — stub.

Real integration would push events using the MISP REST API. The stub
records intent and exits successfully so the rest of the system can be
wired up before a MISP server is available.
"""

from __future__ import annotations

from scry.config import get_settings
from scry.connectors.base import BaseConnector, ConnectorResult
from scry.logging import get_logger

logger = get_logger("misp_stub")


class MispConnector(BaseConnector):
    name = "misp"

    def test_connection(self) -> ConnectorResult:
        s = get_settings()
        if not s.misp_url or not s.misp_key:
            return ConnectorResult(ok=False, detail="MISP URL/key not configured")
        return ConnectorResult(ok=True, detail="(stub) configured")

    def push(self, *, dry_run: bool = True) -> ConnectorResult:
        if dry_run:
            logger.info("misp_push_dry_run")
            return ConnectorResult(ok=True, sent=0, detail="dry run")
        logger.info("misp_push_skipped", reason="stub")
        return ConnectorResult(ok=True, sent=0, detail="stub — no live push")
