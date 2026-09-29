"""Functional tests for the entity / observable detail UI routes.

These routes batch-resolve relationship endpoints (entities vs observables) in
two bulk queries instead of one query per relationship. The tests seed a small
graph and assert the rendered pages resolve related entities and observables
correctly in both directions.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from scry.db import session_scope
from scry.main import app
from scry.models import Entity, Observable, Relationship


def _seed_graph() -> dict[str, int]:
    with session_scope() as s:
        actor = Entity(type="threat_actor", canonical_name="APT-Test", aliases=[], tags=["apt"])
        tool = Entity(type="tool", canonical_name="Cobalt Strike", aliases=[], tags=["tool"])
        ip = Observable(
            type="ipv4",
            value="203.0.113.5",
            normalized_value="203.0.113.5",
            risk_score=88.0,
            actionability="block_if_safe",
        )
        s.add_all([actor, tool, ip])
        s.flush()

        # actor --uses--> tool (entity->entity, both directions exercised)
        s.add(
            Relationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="tool",
                target_id=tool.id,
                relationship_type="uses",
            )
        )
        # actor --communicates_with--> ip (entity->observable)
        s.add(
            Relationship(
                source_type="threat_actor",
                source_id=actor.id,
                target_type="ipv4",
                target_id=ip.id,
                relationship_type="communicates_with",
            )
        )
        s.commit()
        return {"actor": actor.id, "tool": tool.id, "ip": ip.id}


def test_entity_detail_resolves_related_entities_and_observables():
    ids = _seed_graph()
    with TestClient(app) as client:
        r = client.get(f"/ui/entities/{ids['actor']}")
        assert r.status_code == 200
        body = r.text
        # outgoing entity relationship resolved
        assert "Cobalt Strike" in body
        # outgoing observable relationship resolved
        assert "203.0.113.5" in body


def test_entity_detail_incoming_relationship():
    ids = _seed_graph()
    with TestClient(app) as client:
        # The tool is the *target* of the "uses" relationship → appears via in_rels
        r = client.get(f"/ui/entities/{ids['tool']}")
        assert r.status_code == 200
        assert "APT-Test" in r.text


def test_observable_detail_resolves_source_entity():
    ids = _seed_graph()
    with TestClient(app) as client:
        r = client.get(f"/ui/observables/{ids['ip']}")
        assert r.status_code == 200
        # The actor points at this observable → shown as an incoming relationship
        assert "APT-Test" in r.text


def test_entity_detail_404_for_missing():
    with TestClient(app) as client:
        assert client.get("/ui/entities/999999").status_code == 404
