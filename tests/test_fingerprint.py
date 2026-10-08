from __future__ import annotations

import itertools

from hackscan.core.fingerprint import ID_PREFIX, assign_ids, normalize_expression


def test_normalize_expression_ignores_formatting_and_comments():
    a = 'cursor.execute( f"SELECT {x}" )  # comment'
    b = 'cursor.execute(f"SELECT {x}")'
    assert normalize_expression(a) == normalize_expression(b)


def test_normalize_expression_falls_back_on_unparseable():
    assert normalize_expression("if x  ==\n   1:") == "if x == 1:"


def test_id_survives_line_shift(make_finding):
    (a,) = assign_ids([make_finding(line=10)])
    (b,) = assign_ids([make_finding(line=42)])
    assert a.id == b.id
    assert a.id.startswith(ID_PREFIX)


def test_id_is_vendor_independent(make_finding):
    (own,) = assign_ids([make_finding(rule_id="HS-SQLI-001")])
    (sem,) = assign_ids(
        [make_finding(rule_id="semgrep:formatted-sql", sources=("semgrep",), cwe=("CWE-89",))]
    )
    assert own.id == sem.id


def test_id_changes_with_identity_fields(make_finding):
    base = assign_ids([make_finding()])[0].id
    assert assign_ids([make_finding(path="other.py")])[0].id != base
    assert assign_ids([make_finding(function="other_fn")])[0].id != base
    assert assign_ids([make_finding(snippet="cursor.execute(q2)")])[0].id != base
    assert assign_ids([make_finding(rule_id="HS-CMDI-001", cwe=())])[0].id != base


def test_identical_sinks_get_distinct_ids_independent_of_order(make_finding):
    findings = [make_finding(line=n) for n in (30, 10, 20)]
    results = {tuple(f.id for f in assign_ids(p)) for p in itertools.permutations(findings)}
    assert len(results) == 1
    (ids,) = results
    assert len(set(ids)) == 3


def test_id_uses_sink_not_display_snippet(make_finding):
    (a,) = assign_ids([make_finding(sink="cursor.execute(query)", snippet="cursor.execute(query)")])
    (b,) = assign_ids(
        [
            make_finding(
                sink="cursor.execute(query)",
                snippet="query = build()\ncursor.execute(query)",
                sources=("semgrep",),
                rule_id="semgrep:x",
            )
        ]
    )
    assert a.id == b.id


def test_same_location_ties_are_order_independent(make_finding):
    findings = [
        make_finding(rule_id="semgrep:r", sources=("semgrep",), cwe=(), message="first"),
        make_finding(rule_id="semgrep:r", sources=("semgrep",), cwe=(), message="second"),
    ]
    results = {
        tuple((f.message, f.id) for f in assign_ids(p)) for p in itertools.permutations(findings)
    }
    assert len(results) == 1
