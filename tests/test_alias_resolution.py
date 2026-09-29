from scry.alias_resolution import resolve_canonical, upsert_entity


def test_resolves_actor_alias():
    canonical, aliases = resolve_canonical("Cozy Bear", "threat_actor")
    assert canonical == "APT29"
    assert "Cozy Bear" in aliases or any(a.lower() == "cozy bear" for a in aliases)


def test_resolves_malware_alias():
    canonical, _ = resolve_canonical("ALPHV", "malware_family")
    assert canonical == "BlackCat"


def test_upsert_idempotent(session):
    a = upsert_entity(session, surface_form="Cozy Bear", entity_type="threat_actor")
    b = upsert_entity(session, surface_form="NOBELIUM", entity_type="threat_actor")
    assert a.id == b.id  # same canonical
    assert "Cozy Bear" in a.aliases and "NOBELIUM" in a.aliases
