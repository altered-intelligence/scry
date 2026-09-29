from datetime import UTC, datetime, timedelta

from scry.models import Observable
from scry.scoring.lifecycle import LifecycleEngine


def test_decay_expires_old_ip(session):
    old = datetime.now(UTC) - timedelta(days=60)
    ob = Observable(
        type="ipv4",
        value="198.51.100.42",
        normalized_value="198.51.100.42",
        first_seen=old,
        last_seen=old,
        last_reported=old,
        expiration_date=old + timedelta(days=21),
        ttl_days=21,
    )
    session.add(ob)
    session.commit()
    res = LifecycleEngine(session).apply_decay()
    assert res.expired >= 1
    session.refresh(ob)
    assert ob.status == "expired"


def test_cve_never_expires(session):
    long_ago = datetime.now(UTC) - timedelta(days=2000)
    ob = Observable(
        type="cve",
        value="CVE-2020-0001",
        normalized_value="CVE-2020-0001",
        first_seen=long_ago,
        last_seen=long_ago,
        last_reported=long_ago,
        ttl_days=0,
    )
    session.add(ob)
    session.commit()
    LifecycleEngine(session).apply_decay()
    session.refresh(ob)
    assert ob.status != "expired"
