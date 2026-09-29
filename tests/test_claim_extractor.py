from scry.extraction.claim_extractor import ClaimExtractor


def test_exploited_in_the_wild_claim():
    e = ClaimExtractor()
    out = e.extract("CVE-2024-12345 is actively exploited in the wild.")
    types = {c.claim_type for c in out}
    assert "exploited_in_the_wild" in types


def test_victim_claim(fixture_dir):
    e = ClaimExtractor()
    out = e.extract((fixture_dir / "ransomware.txt").read_text())
    types = {c.claim_type for c in out}
    assert "victim_claimed" in types
    assert "ransomware_deployment" in types
    assert "targets_defense_industry" in types


def test_appdomain_claim(fixture_dir):
    e = ClaimExtractor()
    out = e.extract((fixture_dir / "appdomain_hijacking.txt").read_text())
    assert any(c.claim_type == "appdomainmanager_hijacking" for c in out)
