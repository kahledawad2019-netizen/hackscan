from __future__ import annotations

import itertools
from dataclasses import replace

from vulnhawk.core.dedupe import merge_findings
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
