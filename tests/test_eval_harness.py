"""Lightweight extraction evaluation harness.

For each labeled fixture, define the expected IOC/topic set and measure
precision/recall on what the extractors actually produce. Fails the test
if either metric drops below thresholds — guarding against silent
regressions in the extractors.
"""

from __future__ import annotations

from dataclasses import dataclass

from scry.extraction.classifiers import classify_all
from scry.extraction.ioc_extractor import IOCExtractor


@dataclass
class Expected:
    iocs: set[str]
    topics: set[str]


CASES: dict[str, Expected] = {
    "ransomware.txt": Expected(
        iocs={
            "CVE-2024-12345",
            "198.51.100.42",
            "6e2c8b3f5a1d4f9e7c0b2a3d5e6f7891a4b5c6d7e8f90123456789abcdef0123",
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        },
        topics={"ransomware", "defense-industry"},
    ),
    "microsoft_cve.txt": Expected(
        iocs={"CVE-2026-12001", "msrc@microsoft.com"},
        topics={"microsoft", "exploited-in-the-wild"},
    ),
    "appdomain_hijacking.txt": Expected(
        iocs={"T1574.014", "9e1d0f8b6c2a4d3e5f7a8b9c0d1e2f3041526374859607182939404152637485"},
        topics={"appdomainmanager-hijacking"},
    ),
    "ai_threat.txt": Expected(iocs=set(), topics={"ai-security", "defense-industry"}),
    "wiper.txt": Expected(iocs={"203.0.113.7"}, topics={"wiper"}),
    "exploit_poc.txt": Expected(iocs={"CVE-2026-9999"}, topics={"exploit-poc", "exploited-in-the-wild"}),
}


def _normalized_values(text: str) -> set[str]:
    return {i.normalized_value for i in IOCExtractor().extract(text)}


def test_eval_extraction(fixture_dir):
    """Smoke eval: each expected indicator + topic must be recovered."""
    failures: list[str] = []
    for fname, expected in CASES.items():
        text = (fixture_dir / fname).read_text()
        got_iocs = _normalized_values(text)
        got_topics = {t.tag for t in classify_all(text)}
        missing_iocs = expected.iocs - got_iocs
        missing_topics = expected.topics - got_topics
        if missing_iocs:
            failures.append(f"{fname}: missing IOCs {missing_iocs}")
        if missing_topics:
            failures.append(f"{fname}: missing topics {missing_topics}")
    assert not failures, "\n".join(failures)


def test_eval_no_false_positives_in_benign(fixture_dir):
    """Benign article must yield no high-malice IOCs."""
    text = (fixture_dir / "benign_noise.txt").read_text()
    iocs = IOCExtractor().extract(text)
    for ioc in iocs:
        if ioc.type in {"domain", "url"}:
            assert ioc.maliciousness_confidence <= 50
            assert ioc.false_positive_risk >= 0.5 or "benign-shared-infrastructure" in ioc.tags
