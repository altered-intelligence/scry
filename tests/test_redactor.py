from scry.parsing.redactor import redact_secrets


def test_redacts_aws_key():
    r = redact_secrets("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in r.redacted_text
    assert r.counts.get("aws_access_key") == 1


def test_redacts_jwt_and_private_key():
    text = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SIGN\n"
        "-----BEGIN RSA PRIVATE KEY-----\nFAKECONTENTHERE\n-----END RSA PRIVATE KEY-----"
    )
    r = redact_secrets(text)
    assert "BEGIN RSA PRIVATE KEY" not in r.redacted_text
    assert "[REDACTED:private_key_block]" in r.redacted_text


def test_password_assignment():
    r = redact_secrets("password='hunter2'\napi_key: sk-test-1234567890ABC")
    assert "hunter2" not in r.redacted_text
