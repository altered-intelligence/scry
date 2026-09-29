from scry.ingestion.policy import CollectionPolicyEngine


def test_safe_public_web_allowed():
    eng = CollectionPolicyEngine()
    dec = eng.evaluate(policy_name="safe_public_web", source_enabled=True)
    assert dec.allowed and dec.fetch_mode == "text"


def test_disabled_source_blocked():
    eng = CollectionPolicyEngine()
    dec = eng.evaluate(policy_name="safe_public_web", source_enabled=False)
    assert not dec.allowed


def test_unknown_policy_fails_closed():
    eng = CollectionPolicyEngine()
    dec = eng.evaluate(policy_name="not_a_real_policy", source_enabled=True)
    assert not dec.allowed


def test_passive_metadata_blocked_when_darkweb_disabled(monkeypatch):
    monkeypatch.setenv("CTI_ENABLE_DARK_WEB", "false")
    from scry import config

    config.get_settings.cache_clear()
    eng = CollectionPolicyEngine()
    dec = eng.evaluate(policy_name="passive_metadata_only", source_enabled=True)
    assert not dec.allowed
