from scry.extraction.defang import defang, looks_defanged, refang


def test_refang_dot_brackets():
    assert refang("example[.]com") == "example.com"
    assert refang("evil[.]example[.]net") == "evil.example.net"


def test_refang_hxxp():
    assert refang("hxxps://evil[.]example[.]net/path") == "https://evil.example.net/path"
    assert refang("hxxp://1[.]2[.]3[.]4") == "http://1.2.3.4"


def test_refang_email():
    assert refang("user [at] example [dot] com") == "user@example.com"


def test_defang_roundtrip():
    original = "https://example.com/path"
    defanged = defang(original)
    assert "hxxps://" in defanged and "[.]" in defanged
    assert refang(defanged) == original


def test_looks_defanged():
    assert looks_defanged("example[.]com")
    assert looks_defanged("hxxps://x[.]y")
    assert not looks_defanged("https://example.com")
