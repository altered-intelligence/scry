"""Clustering engine.

Groups articles by shared CVEs, shared infrastructure (same registered
domain or ASN), shared malware family mentions, and shared threat actor
mentions. Lightweight union-find — no ML in the MVP.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from scry.models import Article, Cluster, EntityMention, ObservableMention

_METHOD = "shared_iocs_and_entities"


def _uf_make(n: int) -> list[int]:
    return list(range(n))


def _uf_find(p: list[int], i: int) -> int:
    while p[i] != i:
        p[i] = p[p[i]]
        i = p[i]
    return i


def _uf_union(p: list[int], a: int, b: int) -> None:
    ra, rb = _uf_find(p, a), _uf_find(p, b)
    if ra != rb:
        p[rb] = ra


def cluster_articles(session: Session) -> list[Cluster]:
    # Clusters are recomputed from scratch each run: replace the previous set
    # for this method in the same transaction so hourly runs never accumulate
    # duplicate/stale Cluster rows.
    session.execute(delete(Cluster).where(Cluster.method == _METHOD))

    article_ids = [aid for aid, in session.execute(_select_article_ids())]
    if not article_ids:
        session.commit()
        return []
    idx = {aid: i for i, aid in enumerate(article_ids)}
    p = _uf_make(len(article_ids))

    # Shared observables
    by_obs: defaultdict[int, list[int]] = defaultdict(list)
    for ob_id, art_id in session.execute(_select_obs_mentions()):
        by_obs[ob_id].append(art_id)
    for art_list in by_obs.values():
        if len(art_list) < 2:
            continue
        first = idx[art_list[0]]
        for aid in art_list[1:]:
            _uf_union(p, first, idx[aid])

    # Shared entities
    by_entity: defaultdict[int, list[int]] = defaultdict(list)
    for ent_id, art_id in session.execute(_select_entity_mentions()):
        by_entity[ent_id].append(art_id)
    for art_list in by_entity.values():
        if len(art_list) < 2:
            continue
        first = idx[art_list[0]]
        for aid in art_list[1:]:
            _uf_union(p, first, idx[aid])

    groups: defaultdict[int, list[int]] = defaultdict(list)
    for aid, i in idx.items():
        groups[_uf_find(p, i)].append(aid)

    clusters: list[Cluster] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        cluster = Cluster(
            name=None,
            kind="article_cluster",
            method=_METHOD,
            confidence=65,
            members={"article": members},
            description=f"{len(members)} related articles by shared IOCs/entities",
        )
        clusters.append(cluster)
    if clusters:
        session.add_all(clusters)
    session.commit()
    return clusters


def _select_article_ids():
    return select(Article.id)


def _select_obs_mentions():
    return select(ObservableMention.observable_id, ObservableMention.article_id)


def _select_entity_mentions():
    return select(EntityMention.entity_id, EntityMention.article_id)
