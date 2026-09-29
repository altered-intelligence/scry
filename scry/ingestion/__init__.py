"""Ingestion subsystem: source registry, policy engine, fetcher, adapters."""

from scry.ingestion.fetcher import FetchResult, SafeFetcher  # noqa: F401
from scry.ingestion.ingest_engine import IngestionEngine  # noqa: F401
from scry.ingestion.policy import CollectionPolicyEngine, PolicyDecision  # noqa: F401
from scry.ingestion.source_registry import SourceRegistry  # noqa: F401
