from __future__ import annotations

import itertools

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
            line=11,
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
        tuple(f.to_dict()["id"] + repr(f.to_dict()) for f in assign_ids(merge_findings(p)))
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


def test_transitive_overlap_forms_one_cluster(make_finding):
    findings = [
        make_finding(line=1, end_line=3),
        make_finding(line=3, end_line=6, sources=("semgrep",), rule_id="semgrep:x"),
        make_finding(line=6, end_line=8, sources=("bandit",), rule_id="bandit:B608"),
    ]
    (merged,) = merge_findings(findings)
    assert (merged.location.start_line, merged.location.end_line) == (1, 8)


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
