"""Collection policy engine.

Reads policies.yaml + per-source overrides and produces a single decision
object that fetcher + adapters honor. Designed to FAIL CLOSED: any policy
that doesn't exist or is malformed denies fetching.
"""

from __future__ import annotations

from dataclasses import dataclass

from scry.config import get_settings, load_policies


@dataclass
class PolicyDecision:
    allowed: bool
    fetch_mode: str  # text | metadata_only | deny
    allow_javascript: bool
    allow_file_download: bool
    allow_binary_download: bool
    respect_robots_txt: bool
    max_depth: int
    requires_analyst_approval: bool
    safety_mode: str | None
    reason: str = ""


class CollectionPolicyEngine:
    def __init__(self) -> None:
        self._policies_data = load_policies()
        self._policies = self._policies_data.get("policies", {}) or {}
        self._prohibited = self._policies_data.get("prohibited_actions", []) or []

    @property
    def prohibited_actions(self) -> list[str]:
        return list(self._prohibited)

    def evaluate(
        self, *, policy_name: str, source_enabled: bool, source_safety_mode: str | None = None
    ) -> PolicyDecision:
        settings = get_settings()
        if not source_enabled:
            return PolicyDecision(False, "deny", False, False, False, True, 0, False, None, "source disabled")
        spec = self._policies.get(policy_name)
        if spec is None:
            return PolicyDecision(
                False, "deny", False, False, False, True, 0, False, None, f"unknown policy {policy_name!r}"
            )

        # Global env-level safety overrides
        if policy_name == "passive_metadata_only" and not settings.enable_dark_web:
            return PolicyDecision(
                False,
                "deny",
                False,
                False,
                False,
                True,
                0,
                True,
                source_safety_mode or "passive_only",
                "dark web collection disabled globally",
            )

        return PolicyDecision(
            allowed=bool(spec.get("allow_fetch", False)),
            fetch_mode=str(spec.get("fetch_mode", "deny")),
            allow_javascript=bool(spec.get("allow_javascript", False)) and settings.enable_js_rendering,
            allow_file_download=bool(spec.get("allow_file_download", False))
            and settings.enable_file_downloads,
            allow_binary_download=bool(spec.get("allow_binary_download", False))
            and settings.enable_file_downloads,
            respect_robots_txt=bool(spec.get("respect_robots_txt", True)),
            max_depth=int(spec.get("max_depth", 0)),
            requires_analyst_approval=bool(spec.get("requires_analyst_approval", False)),
            safety_mode=spec.get("safety_mode") or source_safety_mode,
            reason="ok",
        )
