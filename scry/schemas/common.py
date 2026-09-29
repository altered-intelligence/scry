"""Shared Pydantic primitives."""

from __future__ import annotations

from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ConfidenceScore(BaseModel):
    value: int = Field(ge=0, le=100)
    rationale: str | None = None


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Disposition(StrEnum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign = "benign"
    duplicate = "duplicate"
    needs_more_research = "needs_more_research"
    escalated = "escalated"
    mitigated = "mitigated"
    expired = "expired"


class PageParams(BaseModel):
    offset: int = 0
    limit: int = Field(default=50, ge=1, le=500)


class Page(BaseModel, Generic[T]):
    total: int
    offset: int
    limit: int
    items: list[T]
