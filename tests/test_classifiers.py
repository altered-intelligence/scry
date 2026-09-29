from scry.extraction.classifiers import classify_all


def test_microsoft_topic(fixture_dir):
    tags = {t.tag for t in classify_all((fixture_dir / "microsoft_cve.txt").read_text())}
    assert "microsoft" in tags and "exploited-in-the-wild" in tags


def test_ransomware_topic(fixture_dir):
    tags = {t.tag for t in classify_all((fixture_dir / "ransomware.txt").read_text())}
    assert "ransomware" in tags
    assert "defense-industry" in tags


def test_appdomain_topic(fixture_dir):
    tags = {t.tag for t in classify_all((fixture_dir / "appdomain_hijacking.txt").read_text())}
    assert "appdomainmanager-hijacking" in tags


def test_ai_topic(fixture_dir):
    tags = {t.tag for t in classify_all((fixture_dir / "ai_threat.txt").read_text())}
    assert "ai-security" in tags


def test_wiper_topic(fixture_dir):
    tags = {t.tag for t in classify_all((fixture_dir / "wiper.txt").read_text())}
    assert "wiper" in tags


def test_exploit_poc_topic(fixture_dir):
    tags = {t.tag for t in classify_all((fixture_dir / "exploit_poc.txt").read_text())}
    assert "exploit-poc" in tags
