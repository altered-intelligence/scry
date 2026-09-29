"""Lightweight ATT&CK mapping enricher.

Maps technique IDs found in text (T1059, T1078, T1546, etc.) to their canonical
names. Bundled dictionary covers the most-cited subset. Not exhaustive — analysts
can extend the dictionary as needed.
"""

from __future__ import annotations

from typing import Any

from scry.enrichment.base import BaseEnricher, EnrichmentOutput

_TECHNIQUES: dict[str, tuple[str, str]] = {
    # technique_id -> (name, tactic)
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036": ("Masquerading", "Defense Evasion"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1047": ("Windows Management Instrumentation", "Execution"),
    "T1053": ("Scheduled Task/Job", "Execution"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.003": ("Windows Command Shell", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1195": ("Supply Chain Compromise", "Initial Access"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"),
    "T1546": ("Event Triggered Execution", "Persistence"),
    "T1547": ("Boot or Logon Autostart Execution", "Persistence"),
    "T1556": ("Modify Authentication Process", "Credential Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1574": ("Hijack Execution Flow", "Defense Evasion"),
    "T1574.014": ("AppDomainManager", "Defense Evasion"),
    "T1583": ("Acquire Infrastructure", "Resource Development"),
    "T1588": ("Obtain Capabilities", "Resource Development"),
}


class AttackMappingEnricher(BaseEnricher):
    name = "attack_mapping"

    def enrich(self, value: str, *, context: dict[str, Any] | None = None) -> EnrichmentOutput:
        tid = value.upper()
        info = _TECHNIQUES.get(tid)
        if not info:
            return EnrichmentOutput(
                fields={"technique_id": tid, "known": False}, rationale=["technique not in local dictionary"]
            )
        name, tactic = info
        return EnrichmentOutput(
            fields={"technique_id": tid, "technique_name": name, "tactic": tactic, "known": True},
            rationale=[f"resolved to {name} ({tactic})"],
        )


def list_known_techniques() -> dict[str, tuple[str, str]]:
    return dict(_TECHNIQUES)
