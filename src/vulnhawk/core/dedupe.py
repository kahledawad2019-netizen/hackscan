"""Cross-source dedupe with a deterministic, order-independent merge policy.

Pipeline order: collect (own engine + importers) -> `merge_findings` -> `assign_ids`.

Clustering is anchor-based, not transitive: findings are visited from most to least
precise (smallest region first), and each joins the first cluster whose *anchor* (the
cluster's first, most precise member) it overlaps. A broad finding spanning two distinct
sinks therefore joins one of them instead of fusing them together.

A finding may join a cluster only when it shares `vuln_class` and path with the anchor,
their regions overlap (column-aware), and both identities are grounded
(see `taxonomy.is_mergeable_class`).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace

from vulnhawk.core.models import OWN_SOURCE, Finding, Region, Status
from vulnhawk.core.taxonomy import is_mergeable_class, normalize_cwes


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Merge duplicates across sources. Output is sorted by `Finding.sort_key`."""
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    singles: list[Finding] = []
    for f in findings:
        if is_mergeable_class(f.vuln_class, f.cwe):
            buckets[(f.vuln_class, f.location.path)].append(f)
        else:
            singles.append(f)

    merged: list[Finding] = list(singles)
    for members in buckets.values():
        for cluster in _anchor_clusters(members):
            merged.append(_merge_cluster(cluster) if len(cluster) > 1 else cluster[0])
    merged.sort(key=Finding.sort_key)
    return merged


def _precision_key(f: Finding) -> tuple:
    """Total order: own engine first, then most precise region, then full content."""
    return (
        OWN_SOURCE not in f.sources,
        f.location.span,
        f.location.start_pos,
        f.canonical_json(),
    )


def _anchor_clusters(members: list[Finding]) -> list[list[Finding]]:
    clusters: list[list[Finding]] = []
    for f in sorted(members, key=_precision_key):
        for cluster in clusters:
            if cluster[0].location.overlaps(f.location):
                cluster.append(f)
                break
        else:
            clusters.append([f])
    return clusters


def _primary(cluster: list[Finding]) -> Finding:
    """Own-engine finding wins; otherwise the lexicographically smallest rule id."""
    own = [f for f in cluster if OWN_SOURCE in f.sources]
    pool = own or cluster
    return min(pool, key=lambda f: (f.rule_id, f.canonical_json()))


def _merge_cluster(cluster: list[Finding]) -> Finding:
    primary = _primary(cluster)
    ordered = sorted(cluster, key=lambda f: f.canonical_json())
    status = max((f.status for f in cluster), key=lambda s: s.rank)
    suppression = None
    if status is Status.SUPPRESSED:
        suppression = ";".join(sorted({f.suppression for f in cluster if f.suppression}))

    rules = {f.rule_id for f in cluster} | {r for f in cluster for r in f.related_rules}
    rules.discard(primary.rule_id)

    # Concatenation (duplicates kept: each contributor's evidence stands on its own).
    evidence = sorted(
        (e for f in cluster for e in f.evidence),
        key=lambda e: (e.producer, e.kind, e.message, e.region.sort_key() if e.region else ()),
    )
    fix = primary.fix or next((f.fix for f in ordered if f.fix is not None), None)

    return replace(
        primary,
        location=_union(f.location for f in cluster),
        severity=max((f.severity for f in cluster), key=lambda s: s.rank),
        confidence=max(f.confidence for f in cluster),
        status=status,
        suppression=suppression,
        sources=tuple(sorted({s for f in cluster for s in f.sources})),
        related_rules=tuple(sorted(rules)),
        cwe=normalize_cwes(c for f in cluster for c in f.cwe),
        evidence=tuple(evidence),
        fix=fix,
    )


def _union(regions: Iterable[Region]) -> Region:
    """Smallest region covering every contributor."""
    regions = list(regions)
    first = min(regions, key=lambda r: r.start_pos)
    last = max(regions, key=lambda r: r.end_pos)
    return Region(
        path=first.path,
        start_line=first.start_line,
        start_column=first.start_column,
        end_line=last.end_line,
        end_column=last.end_column,
    )
