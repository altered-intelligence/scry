from scry.extraction.ioc_extractor import IOCExtractor


def test_extracts_public_ipv4():
    e = IOCExtractor()
    out = e.extract("Beacon to 198.51.100.42 observed.")
    assert any(i.type == "ipv4" and i.normalized_value == "198.51.100.42" for i in out)


def test_skips_private_ipv4():
    e = IOCExtractor()
    out = e.extract("Internal host 10.0.0.5 spoke to 192.168.1.50.")
    assert not any(i.type == "ipv4" for i in out)


def test_defanged_ipv4():
    e = IOCExtractor()
    out = e.extract("Connected to 198[.]51[.]100[.]42")
    assert any(i.type == "ipv4" and i.normalized_value == "198.51.100.42" for i in out)


def test_extracts_domain_and_skips_version_string():
    e = IOCExtractor()
    out = e.extract("evil.example.net and version 1.2.3 are different.")
    types = {i.type for i in out}
    assert "domain" in types
    assert not any(i.type == "domain" and i.normalized_value == "1.2.3" for i in out)


def test_defanged_domain():
    e = IOCExtractor()
    out = e.extract("Contacted evil[.]example[.]net")
    assert any(i.type == "domain" and i.normalized_value == "evil.example.net" for i in out)


def test_cve_normalization():
    e = IOCExtractor()
    out = e.extract("Vulnerability cve-2024-12345 was exploited")
    assert any(i.type == "cve" and i.normalized_value == "CVE-2024-12345" for i in out)


def test_url_extraction_and_refang():
    e = IOCExtractor()
    out = e.extract("Phishing at hxxps://login[.]example[.]net/auth.")
    urls = [i for i in out if i.type == "url"]
    assert urls and urls[0].normalized_value.startswith("https://login.example.net")


def test_hash_extraction():
    e = IOCExtractor()
    text = (
        "MD5 d41d8cd98f00b204e9800998ecf8427e "
        "SHA256 6e2c8b3f5a1d4f9e7c0b2a3d5e6f7891a4b5c6d7e8f90123456789abcdef0123"
    )
    out = e.extract(text)
    assert any(i.type == "md5" for i in out)
    assert any(i.type == "sha256" for i in out)


def test_email_extraction():
    e = IOCExtractor()
    out = e.extract("Contact attacker@evil.example.net or admin [at] evil [dot] net")
    emails = [i for i in out if i.type == "email"]
    assert any(i.normalized_value == "attacker@evil.example.net" for i in emails)


def test_benign_infrastructure_tag():
    e = IOCExtractor()
    out = e.extract("Reference: https://github.com/microsoft/security-advisories")
    domains = [i for i in out if i.type in ("domain", "url")]
    assert any("benign-shared-infrastructure" in i.tags for i in domains)


def test_attack_technique_extraction():
    e = IOCExtractor()
    out = e.extract("Observed techniques: T1486 and T1059.001.")
    assert {"T1486", "T1059.001"} <= {i.normalized_value for i in out if i.type == "attack_technique"}
