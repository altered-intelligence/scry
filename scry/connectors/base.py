"""Base connector interface for future integrations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ConnectorResult:
    ok: bool
    sent: int = 0
    failed: int = 0
    detail: str = ""


class BaseConnector(ABC):
    name: str = "base"

    @abstractmethod
    def test_connection(self) -> ConnectorResult: ...

    @abstractmethod
    def push(self, *, dry_run: bool = True) -> ConnectorResult: ...
