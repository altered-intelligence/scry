"""OpenCTI connector — stub."""

from __future__ import annotations

from scry.config import get_settings
from scry.connectors.base import BaseConnector, ConnectorResult
from scry.logging import get_logger

logger = get_logger("opencti_stub")


class OpenCTIConnector(BaseConnector):
    name = "opencti"

    def test_connection(self) -> ConnectorResult:
        s = get_settings()
        if not s.opencti_url or not s.opencti_key:
            return ConnectorResult(ok=False, detail="OpenCTI URL/key not configured")
        return ConnectorResult(ok=True, detail="(stub) configured")

    def push(self, *, dry_run: bool = True) -> ConnectorResult:
        if dry_run:
            logger.info("opencti_push_dry_run")
            return ConnectorResult(ok=True, sent=0, detail="dry run")
        logger.info("opencti_push_skipped", reason="stub")
        return ConnectorResult(ok=True, sent=0, detail="stub — no live push")
