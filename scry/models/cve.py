"""CVE model + Microsoft vulnerability surface fields."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from scry.models.base import Base, IdMixin, TimestampMixin


class CVE(Base, IdMixin, TimestampMixin):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    affected_versions: Mapped[list] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list)
    cpe_uris: Mapped[list] = mapped_column(JSON, default=list)
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v4: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    # v0.8.0 step 2 — FIRST.org EPSS percentile + enrichment timestamp (TTL refresh).
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_enriched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exploited_in_the_wild: Mapped[bool] = mapped_column(Boolean, default=False)
    public_poc_available: Mapped[bool] = mapped_column(Boolean, default=False)
    metasploit_module: Mapped[bool] = mapped_column(Boolean, default=False)
    nuclei_template: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    workaround_available: Mapped[bool] = mapped_column(Boolean, default=False)
    ransomware_associated: Mapped[bool] = mapped_column(Boolean, default=False)
    is_microsoft: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attack_vector: Mapped[str | None] = mapped_column(String(32), nullable=True)
    privileges_required: Mapped[str | None] = mapped_column(String(16), nullable=True)
    user_interaction: Mapped[str | None] = mapped_column(String(16), nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    recommended_mitigation: Mapped[str | None] = mapped_column(Text, nullable=True)
