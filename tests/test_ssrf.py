import pytest

from scry.ingestion.ssrf import evaluate_url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/admin",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5",
        "file:///etc/passwd",
        "gopher://example.com",
    ],
)
def test_dangerous_urls_blocked(url):
    res = evaluate_url(url)
    assert not res.allowed, res.reason


def test_onion_blocked_by_default():
    res = evaluate_url("http://abc1234567xyz890.onion/")
    assert not res.allowed


def test_normal_https_allowed():
    res = evaluate_url("https://example.com/")
    assert res.allowed or "resolution failed" in res.reason
