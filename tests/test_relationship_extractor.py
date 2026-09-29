from scry.extraction.entity_extractor import EntityExtractor
from scry.extraction.ioc_extractor import IOCExtractor
from scry.extraction.relationship_extractor import RelationshipExtractor


def test_actor_uses_malware():
    text = "APT29 uses Cobalt Strike to maintain persistence."
    iocs = IOCExtractor().extract(text)
    entities = EntityExtractor().extract(text)
    rels = RelationshipExtractor().extract(text, iocs=iocs, entities=entities)
    assert any(r.relationship_type == "uses" and r.target_value.lower().startswith("cobalt") for r in rels)


def test_actor_exploits_cve():
    text = "LockBit exploited CVE-2024-12345 to gain initial access."
    iocs = IOCExtractor().extract(text)
    entities = EntityExtractor().extract(text)
    rels = RelationshipExtractor().extract(text, iocs=iocs, entities=entities)
    assert any(r.relationship_type == "exploits" and r.target_type == "cve" for r in rels)


def test_actor_associated_with_domain():
    text = "APT41 communicated with bad-cdn.example.net for C2."
    iocs = IOCExtractor().extract(text)
    entities = EntityExtractor().extract(text)
    rels = RelationshipExtractor().extract(text, iocs=iocs, entities=entities)
    types = {r.relationship_type for r in rels}
    assert "communicates_with" in types or "associated_with" in types
