"""Base enricher interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichmentOutput:
    fields: dict[str, Any] = field(default_factory=dict)
    confidence_delta: int = 0
    rationale: list[str] = field(default_factory=list)


class BaseEnricher(ABC):
    name: str = "base"
    requires_network: bool = False

    @abstractmethod
    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput: ...
