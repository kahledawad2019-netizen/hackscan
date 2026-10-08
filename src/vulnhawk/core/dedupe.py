"""Cross-source dedupe with a deterministic, order-independent merge policy.

Pipeline order: collect (own engine + importers) -> `merge_findings` -> `assign_ids`.

Two findings merge when they share `vuln_class` and path, their line ranges overlap
(transitively), and both have a grounded identity (see `taxonomy.is_mergeable_class`).
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
        for cluster in _overlap_clusters(members):
            merged.append(_merge_cluster(cluster) if len(cluster) > 1 else cluster[0])
    merged.sort(key=Finding.sort_key)
    return merged


def _canonical_key(f: Finding) -> tuple:
    """Total order on findings, independent of input order."""
    return (
        *f.location.sort_key(),
        f.location.end_line,
        f.rule_id,
        f.sources,
        f.snippet,
        f.message,
    )


def _overlap_clusters(members: list[Finding]) -> list[list[Finding]]:
    """Group findings whose line ranges overlap, transitively (interval sweep)."""
    ordered = sorted(members, key=_canonical_key)
    clusters: list[list[Finding]] = []
    cluster_end = -1
    for f in ordered:
        if clusters and f.location.start_line <= cluster_end:
            clusters[-1].append(f)
            cluster_end = max(cluster_end, f.location.end_line)
        else:
            clusters.append([f])
            cluster_end = f.location.end_line
    return clusters


def _primary(cluster: list[Finding]) -> Finding:
    """Own-engine finding wins; otherwise the lexicographically smallest rule id."""
    own = [f for f in cluster if OWN_SOURCE in f.sources]
    pool = own or cluster
    return min(pool, key=lambda f: (f.rule_id, *_canonical_key(f)))


def _merge_cluster(cluster: list[Finding]) -> Finding:
    primary = _primary(cluster)
    status = max((f.status for f in cluster), key=lambda s: s.rank)
    suppression = None
    if status is Status.SUPPRESSED:
        suppression = ";".join(sorted({f.suppression for f in cluster if f.suppression}))

    rules = {f.rule_id for f in cluster} | {r for f in cluster for r in f.related_rules}
    rules.discard(primary.rule_id)

    evidence = sorted(
        {e for f in cluster for e in f.evidence},
        key=lambda e: (e.producer, e.kind, e.message, e.region.sort_key() if e.region else ()),
    )
    fix = primary.fix or next(
        (f.fix for f in sorted(cluster, key=_canonical_key) if f.fix is not None), None
    )

    return replace(
        primary,
        location=_span(cluster, primary.location),
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


def _span(cluster: list[Finding], primary: Region) -> Region:
    """Keep the primary's start position; extend the end to cover the whole cluster."""
    end_line = max(f.location.end_line for f in cluster)
    end_column = primary.end_column if end_line == primary.end_line else None
    return replace(primary, end_line=end_line, end_column=end_column)
