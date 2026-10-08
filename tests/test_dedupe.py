from __future__ import annotations

import itertools
import random
from dataclasses import replace

from vulnhawk.core.dedupe import _anchor_clusters, merge_findings
from vulnhawk.core.fingerprint import assign_ids
from vulnhawk.core.models import Evidence, Severity, Status


def _cross_tool_sqli(make_finding):
    return [
        make_finding(
            rule_id="VH-SQLI-001",
            line=10,
            severity=Severity.HIGH,
            confidence=80,
            evidence=(Evidence("taint", "taint_step", "uid <- request.args"),),
        ),
        make_finding(
            rule_id="semgrep:formatted-sql",
            sources=("semgrep",),
            line=10,
            end_line=11,
            severity=Severity.CRITICAL,
            confidence=60,
            evidence=(Evidence("semgrep", "tool_message", "Detected SQL string formatting"),),
        ),
        make_finding(
            rule_id="bandit:B608",
            sources=("bandit",),
            cwe=(),
            line=10,
            severity=Severity.MEDIUM,
            confidence=40,
        ),
    ]


def test_cross_tool_merge(make_finding):
    (merged,) = merge_findings(_cross_tool_sqli(make_finding))
    assert merged.rule_id == "VH-SQLI-001"  # own engine is primary
    assert merged.related_rules == ("bandit:B608", "semgrep:formatted-sql")
    assert merged.sources == ("bandit", "semgrep", "vulnhawk")
    assert merged.severity is Severity.CRITICAL
    assert merged.confidence == 80
    assert merged.cwe == ("CWE-89",)
    assert [e.producer for e in merged.evidence] == ["semgrep", "taint"]
    assert (merged.location.start_line, merged.location.end_line) == (10, 11)


def test_merge_is_order_independent(make_finding):
    findings = _cross_tool_sqli(make_finding) + [
        make_finding(rule_id="VH-CMDI-001", cwe=(), line=10, snippet="os.system(cmd)"),
        make_finding(line=50, snippet="cursor.execute(q)"),
        make_finding(rule_id="semgrep:no-cwe", sources=("semgrep",), cwe=(), line=10),
    ]
    outputs = {
        tuple(f.canonical_json() for f in assign_ids(merge_findings(p)))
        for p in itertools.permutations(findings)
    }
    assert len(outputs) == 1


def test_no_merge_across_class_path_or_gap(make_finding):
    findings = [
        make_finding(line=10),
        make_finding(line=10, rule_id="VH-CMDI-001", cwe=()),
        make_finding(line=10, path="other.py"),
        make_finding(line=12),
    ]
    assert len(merge_findings(findings)) == 4


def test_unmapped_without_cwe_never_merges(make_finding):
    findings = [
        make_finding(rule_id="semgrep:no-cwe", sources=("semgrep",), cwe=(), line=10),
        make_finding(rule_id="semgrep:no-cwe", sources=("semgrep",), cwe=(), line=10),
    ]
    assert len(merge_findings(findings)) == 2


def test_broad_finding_does_not_fuse_distinct_sinks(make_finding):
    findings = [
        make_finding(line=10, snippet="cursor.execute(a)"),
        make_finding(line=12, snippet="cursor.execute(b)"),
        make_finding(line=10, end_line=12, sources=("semgrep",), rule_id="semgrep:x"),
    ]
    merged = merge_findings(findings)
    assert len(merged) == 2
    assert [m.sources for m in merged] == [("semgrep", "vulnhawk"), ("vulnhawk",)]


def test_distinct_sinks_on_same_line_stay_separate(make_finding):
    def at(col, end_col, **kw):
        f = make_finding(line=10, **kw)
        loc = replace(f.location, start_column=col, end_column=end_col)
        return replace(f, location=loc)

    findings = [at(1, 10), at(20, 30, rule_id="semgrep:x", sources=("semgrep",))]
    assert len(merge_findings(findings)) == 2
    # A whole-line report (no columns) overlaps both, but joins only one.
    whole_line = make_finding(line=10, rule_id="bandit:B608", sources=("bandit",), cwe=())
    assert len(merge_findings([*findings, whole_line])) == 2


def test_merged_location_covers_all_contributors(make_finding):
    findings = [
        make_finding(line=12),
        make_finding(line=10, end_line=12, sources=("semgrep",), rule_id="semgrep:x"),
    ]
    (merged,) = merge_findings(findings)
    assert merged.rule_id == "VH-SQLI-001"
    assert (merged.location.start_line, merged.location.end_line) == (10, 12)


def test_duplicate_evidence_is_kept(make_finding):
    ev = (Evidence("semgrep", "tool_message", "same"),)
    findings = [
        make_finding(evidence=ev),
        make_finding(rule_id="semgrep:x", sources=("semgrep",), evidence=ev),
    ]
    (merged,) = merge_findings(findings)
    assert len(merged.evidence) == 2


def test_tie_on_function_is_order_independent(make_finding):
    findings = [
        make_finding(rule_id="semgrep:x", sources=("semgrep",), function=None),
        make_finding(rule_id="semgrep:x", sources=("semgrep",), function="get_user"),
    ]
    outputs = {
        tuple(f.canonical_json() for f in assign_ids(merge_findings(p)))
        for p in itertools.permutations(findings)
    }
    assert len(outputs) == 1


def test_status_precedence(make_finding):
    suppressed = dict(status=Status.SUPPRESSED, suppression="taint:constant_input")
    one_open = [
        make_finding(**suppressed),
        make_finding(rule_id="semgrep:x", sources=("semgrep",)),
    ]
    assert merge_findings(one_open)[0].status is Status.CANDIDATE

    all_suppressed = [
        make_finding(**suppressed),
        make_finding(
            rule_id="semgrep:x",
            sources=("semgrep",),
            status=Status.SUPPRESSED,
            suppression="inline:# vulnhawk: ignore",
        ),
    ]
    (merged,) = merge_findings(all_suppressed)
    assert merged.status is Status.SUPPRESSED
    assert merged.suppression == "inline:# vulnhawk: ignore;taint:constant_input"

    confirmed = [make_finding(status=Status.CONFIRMED), make_finding(**suppressed)]
    assert merge_findings(confirmed)[0].status is Status.CONFIRMED


def test_primary_without_own_engine_is_smallest_rule(make_finding):
    findings = [
        make_finding(rule_id="semgrep:z", sources=("semgrep",)),
        make_finding(rule_id="bandit:B608", sources=("bandit",), cwe=()),
    ]
    assert merge_findings(findings)[0].rule_id == "bandit:B608"


def _cols(f, col, end_col):
    return replace(f, location=replace(f.location, start_column=col, end_column=end_col))


def test_broad_own_engine_finding_does_not_fuse_distinct_sinks(make_finding):
    findings = [
        make_finding(line=10, end_line=12),  # broad, own engine
        make_finding(line=10, rule_id="semgrep:x", sources=("semgrep",), sink="execute(a)"),
        make_finding(line=12, rule_id="semgrep:x", sources=("semgrep",), sink="execute(b)"),
    ]
    merged = merge_findings(findings)
    assert len(merged) == 2
    # The own-engine finding still wins primary in the cluster it joined.
    assert sum("vulnhawk" in m.sources for m in merged) == 1


def test_union_with_zero_width_region_covers_all(make_finding):
    point = _cols(make_finding(), 6, 6)
    span = _cols(make_finding(rule_id="semgrep:x", sources=("semgrep",)), 5, 7)
    (merged,) = merge_findings([point, span])
    assert merged.location.start_column == 5
    assert merged.location.overlaps(point.location)
    assert merged.location.overlaps(span.location)
    assert merged.location.end_column == 7


def test_merge_keeps_a_recorded_sink(make_finding):
    findings = [
        make_finding(sink=""),
        make_finding(rule_id="semgrep:x", sources=("semgrep",), sink="cursor.execute(q)"),
    ]
    (merged,) = merge_findings(findings)
    assert merged.sink == "cursor.execute(q)"
    (with_id,) = assign_ids([merged])
    (reference,) = assign_ids([make_finding(sink="cursor.execute(q)")])
    assert with_id.id == reference.id


def test_randomized_order_independence(make_finding):
    """Random mixes of sources, spans, columns and sinks: output never depends on order."""
    rng = random.Random(1234)
    tools = [
        ("VH-SQLI-001", ("vulnhawk",)),
        ("semgrep:x", ("semgrep",)),
        ("bandit:B608", ("bandit",)),
    ]
    for _ in range(200):
        findings = []
        for _ in range(rng.randint(2, 7)):
            rule, src = rng.choice(tools)
            line = rng.randint(1, 4)
            f = make_finding(
                rule_id=rule,
                sources=src,
                line=line,
                end_line=line + rng.choice([0, 0, 1, 2]),
                sink=rng.choice(["", "execute(a)", "execute(b)"]),
                function=rng.choice([None, "f", "g"]),
                confidence=rng.randint(0, 100),
            )
            if rng.random() < 0.5 and f.location.end_line == f.location.start_line:
                col = rng.randint(1, 20)
                f = _cols(f, col, col + rng.randint(0, 10))
            findings.append(f)
        for cluster in _anchor_clusters(findings):
            assert all(a.location.overlaps(b.location) for a in cluster for b in cluster)
        baseline = [f.canonical_json() for f in assign_ids(merge_findings(findings))]
        for _ in range(5):
            shuffled = findings[:]
            rng.shuffle(shuffled)
            assert [f.canonical_json() for f in assign_ids(merge_findings(shuffled))] == baseline
            assert len(baseline) <= len(findings)


def _multiline(f, line, col, end_line, end_col):
    loc = replace(
        f.location, start_line=line, start_column=col, end_line=end_line, end_column=end_col
    )
    return replace(f, location=loc)


def test_broad_multiline_region_does_not_fuse_distinct_sinks(make_finding):
    """Codex repro: 10:1-11:30 overlaps both 10:5-11:10 and 11:20-12:5, which are disjoint."""
    broad = _multiline(make_finding(), 10, 1, 11, 30)
    a = _multiline(make_finding(rule_id="semgrep:x", sources=("semgrep",)), 10, 5, 11, 10)
    b = _multiline(make_finding(rule_id="bandit:B608", sources=("bandit",)), 11, 20, 12, 5)
    for order in itertools.permutations([broad, a, b]):
        merged = merge_findings(order)
        assert len(merged) == 2


def test_short_bridge_region_does_not_fuse_distinct_sinks(make_finding):
    """Even when the bridging report is the *smallest* region, disjoint sinks stay apart."""
    a = _cols(make_finding(), 1, 10)
    b = _cols(make_finding(rule_id="semgrep:x", sources=("semgrep",)), 12, 22)
    bridge = _cols(make_finding(rule_id="bandit:B608", sources=("bandit",)), 8, 14)
    assert len(merge_findings([a, b, bridge])) == 2


def test_nested_sinks_from_same_source_stay_separate(make_finding):
    """eval(eval(x)): inner and outer calls overlap but are two findings."""
    outer = _cols(make_finding(rule_id="VH-CODEI-001", cwe=(), sink="eval(eval(x))"), 5, 18)
    inner = _cols(make_finding(rule_id="VH-CODEI-001", cwe=(), sink="eval(x)"), 10, 17)
    assert len(merge_findings([outer, inner])) == 2
    # A different tool reporting the outer call still merges with one of them.
    tool = _cols(
        make_finding(rule_id="bandit:B307", sources=("bandit",), cwe=(), sink="eval(eval(x))"),
        5,
        18,
    )
    assert len(merge_findings([outer, inner, tool])) == 2


def test_same_source_same_sink_still_merges(make_finding):
    a = make_finding(sink="cursor.execute(q)")
    b = make_finding(sink="cursor.execute( q )", rule_id="VH-SQLI-002")
    assert len(merge_findings([a, b])) == 1


def test_merged_id_does_not_depend_on_which_report_has_function(make_finding):
    with_fn = make_finding(
        rule_id="semgrep:x", sources=("semgrep",), sink="q()", function="get_user"
    )
    without = make_finding(rule_id="bandit:B608", sources=("bandit",), sink="q()", function=None)
    (alone,) = assign_ids(merge_findings([with_fn]))
    (both,) = assign_ids(merge_findings([with_fn, without]))
    assert both.function == "get_user"
    assert alone.id == both.id
