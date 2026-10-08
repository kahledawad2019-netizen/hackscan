from __future__ import annotations

import pytest

from hackscan.core.taxonomy import classify, is_mergeable_class, normalize_cwe, normalize_cwes


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("CWE-89", "CWE-89"), ("cwe-089: SQL Injection", "CWE-89"), ("CWE_78", "CWE-78"), ("x", None)],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_normalize_cwes_sorted_numerically_and_deduped():
    assert normalize_cwes(["CWE-798", "cwe-89", "CWE-89", "junk"]) == ("CWE-89", "CWE-798")


@pytest.mark.parametrize(
    ("rule_id", "cwes", "expected"),
    [
        ("HS-SQLI-001", (), "sqli"),
        ("HS-CMDI-002", (), "cmdi"),
        ("HS-CODEI-001", (), "codei"),
        ("HS-CRYPTO-001", (), "weak_crypto"),
        ("bandit:B608", (), "sqli"),
        ("bandit:B602", (), "cmdi"),
        ("gitleaks:aws-access-token", (), "secret"),
        ("semgrep:python.lang.security.audit.formatted-sql-query", ("CWE-89",), "sqli"),
        ("codeql:py/command-line-injection", ("external/cwe/cwe-078",), "cmdi"),
        ("semgrep:some.xss.rule", ("CWE-79",), "other:CWE-79"),
        ("semgrep:no-cwe-rule", (), "other:semgrep:no-cwe-rule"),
    ],
)
def test_classify(rule_id, cwes, expected):
    assert classify(rule_id, cwes) == expected


def test_own_rule_prefix_beats_cwe():
    assert classify("HS-SQLI-001", ("CWE-78",)) == "sqli"


def test_mergeability():
    assert is_mergeable_class("sqli", ())
    assert is_mergeable_class("other:CWE-79", ("CWE-79",))
    assert not is_mergeable_class("other:semgrep:no-cwe-rule", ())
