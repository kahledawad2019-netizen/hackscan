from __future__ import annotations

import ast
from dataclasses import replace
from itertools import permutations

import pytest

from hackscan.analyzers.ast_pass import analyze_source
from hackscan.core.models import Evidence, Fix, FixEdit
from hackscan.core.redact import (
    REDACTED,
    file_secret_literal_values,
    mask_secret_literals,
    redact_findings,
    redact_secretish,
    redact_text,
    secret_literal_values,
)
from hackscan.plugins.loader import builtin_plugins


def test_equal_length_secrets_redact_in_stable_order():
    secrets = ("ABCDE", "BCDEF", "XYZAB")
    for ordered in permutations(secrets):
        assert redact_text("ABCDEF", ordered, literals=False) == f"{REDACTED}F"
        assert redact_text("ABCDEF", set(ordered), literals=False) == f"{REDACTED}F"


def test_only_secret_like_source_values_become_report_wide_secrets():
    source = (
        'token_type = "Bearer"\n'
        'auth_mode = "basic"\n'
        'api_key = "password"\n'
        'api_token = "secret-abc123"\n'
        'password = "hunter2hunter2"\n'
        'auth_key = "correcthorsebatterystaple"\n'
    )
    tree = ast.parse(source)
    assert "Bearer" not in mask_secret_literals(source, tree)
    assert secret_literal_values(tree) == {
        "secret-abc123",
        "hunter2hunter2",
        "correcthorsebatterystaple",
    }


def test_file_secret_values_include_short_strings_bytes_and_multiline_parts():
    tree = ast.parse('api_token = b"hunter2"\npassword = """  abcd  \n  efgh  """\n')
    values = file_secret_literal_values(tree)
    assert {"hunter2", "abcd", "efgh"} <= values
    assert "hunter2" not in secret_literal_values(tree)


@pytest.mark.parametrize(
    ("literal", "value"),
    [
        ("123456789012", "123456789012"),
        ("-123456789012", "-123456789012"),
        ("0x123456789abc", str(0x123456789ABC)),
        ("12.3456789012", "12.3456789012"),
        ("123456789012j", "123456789012j"),
    ],
)
def test_numeric_secret_literals_are_masked_and_collected(literal, value):
    source = f"api_token = {literal}\n"
    tree = ast.parse(source)
    assert literal not in mask_secret_literals(source, tree)
    assert value in secret_literal_values(tree)
    assert {literal, value} <= file_secret_literal_values(tree, source)


@pytest.mark.parametrize("sign", ["-", "+"])
def test_signed_numeric_secret_collects_unsigned_value_and_source_spelling(sign):
    source = f"pin_secret = {sign}0x3ade68b1\n"
    tree = ast.parse(source)
    assert f"{sign}0x3ade68b1" not in mask_secret_literals(source, tree)
    assert {"0x3ade68b1", "987654321"} <= file_secret_literal_values(tree, source)
    assert {"0x3ade68b1", "987654321"} <= secret_literal_values(tree, source)


def test_non_secret_numbers_and_non_numeric_constants_are_untouched():
    source = "timeout = 30\nmax_tokens = 4096\napi_token = True\npassword = None\n"
    tree = ast.parse(source)
    masked = mask_secret_literals(source, tree)
    assert "timeout = 30" in masked
    assert "max_tokens = 4096" not in masked
    assert "api_token = True" in masked
    assert "password = None" in masked
    assert "30" not in file_secret_literal_values(tree, source)
    assert "True" not in file_secret_literal_values(tree, source)
    assert "None" not in file_secret_literal_values(tree, source)


def test_constant_secret_concatenation_is_collected_without_folding_mixed_values():
    source = (
        'password = ("abc" + ("def"))\n'
        'api_key = b"ab" + b"cdef"\n'
        'auth_token = "abc123" + "def456"\n'
        'credential = "pre" + user\n'
        'password = "foo" + user + "bar"\n'
    )
    tree = ast.parse(source)
    assert {"abcdef", "abc123def456"} <= file_secret_literal_values(tree, source)
    assert "abcdef" not in secret_literal_values(tree)
    assert "abc123def456" in secret_literal_values(tree)
    assert "pre" not in file_secret_literal_values(tree, source)
    assert "foobar" not in file_secret_literal_values(tree, source)


def test_file_secret_redacts_all_finding_text_fields():
    (candidate,) = analyze_source(
        "import os\ndef run(cmd): os.system(cmd)\n", "a.py", builtin_plugins()
    ).findings
    finding = replace(
        candidate,
        rule_id="tool:hunter2",
        related_rules=("another:hunter2",),
        message="hunter2",
        evidence=(Evidence("tool", "message", "hunter2"),),
        snippet="hunter2",
        sink="hunter2",
        fix=Fix("replace hunter2", (FixEdit(candidate.location, "hunter2"),), "tool"),
    )
    (clean,) = redact_findings([finding], (), file_secrets={"a.py": {"hunter2"}})
    assert "hunter2" not in str(clean.to_dict())


@pytest.mark.parametrize("scope", ["report", "tool", "file"])
def test_rule_metadata_redacts_each_secret_scope(scope):
    (candidate,) = analyze_source(
        "import os\ndef run(cmd): os.system(cmd)\n", "a.py", builtin_plugins()
    ).findings
    finding = replace(candidate, rule_id="tool:hunter2", related_rules=("other:hunter2",))
    kwargs = {
        "report": {"secrets": {"hunter2"}},
        "tool": {"secrets": (), "tool_secrets": {"hunter2"}},
        "file": {"secrets": (), "file_secrets": {"a.py": {"hunter2"}}},
    }[scope]
    (clean,) = redact_findings([finding], **kwargs)
    assert clean.rule_id == "tool:<REDACTED>"
    assert clean.related_rules == ("other:<REDACTED>",)


@pytest.mark.parametrize("scope", ["report", "tool", "file"])
def test_function_redacts_each_secret_scope(scope):
    (candidate,) = analyze_source(
        "import os\ndef hunter2(cmd): os.system(cmd)\n", "a.py", builtin_plugins()
    ).findings
    kwargs = {
        "report": {"secrets": {"hunter2"}},
        "tool": {"secrets": (), "tool_secrets": {"hunter2"}},
        "file": {"secrets": (), "file_secrets": {"a.py": {"hunter2"}}},
    }[scope]
    (clean,) = redact_findings([candidate], **kwargs)
    assert clean.function == "<REDACTED>"


@pytest.mark.parametrize(
    "source",
    [
        'def run(cmd, password="default-secret-123"): return cmd',
        'async def run(cmd, *, api_token="default-secret-123"): return cmd',
        'handler = lambda cmd, token="default-secret-123": cmd',
        'def run(cmd, /, password=("default-" "secret-123")): return cmd',
    ],
)
def test_secret_named_parameter_defaults_are_masked(source):
    tree = ast.parse(source)
    assert "default-secret-123" not in mask_secret_literals(source, tree)
    assert "default-secret-123" in secret_literal_values(tree)


def test_secretish_redaction_preserves_assignment_spacing():
    assert redact_secretish('secret_salt="x"') == 'secret_salt="<REDACTED>"'
    assert redact_secretish("secret_salt  =  'x'") == "secret_salt  =  '<REDACTED>'"


def test_short_tool_secret_is_redacted_from_secret_class_finding():
    (candidate,) = analyze_source(
        "import os\ndef run(cmd): os.system(cmd)\n", "a.py", builtin_plugins()
    ).findings
    finding = replace(candidate, vuln_class="secret", snippet="credential abc", sink="abc")
    (clean,) = redact_findings([finding], (), tool_secrets={"abc"})
    assert "abc" not in clean.snippet + clean.sink
