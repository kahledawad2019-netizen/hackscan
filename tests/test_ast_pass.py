from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from hackscan.analyzers.ast_pass import analyze_file, analyze_source
from hackscan.core.dedupe import merge_findings
from hackscan.core.fingerprint import assign_ids
from hackscan.core.models import Severity
from hackscan.plugins.base import Match, RulePlugin
from hackscan.plugins.loader import PluginError, builtin_plugins, load_plugins, resolve_plugins


def scan(code: str):
    return analyze_source(textwrap.dedent(code), "app/mod.py", builtin_plugins())


def test_finding_fields_from_ast():
    result = scan(
        """
        import os

        class Api:
            def run(self, host):
                os.system("ping " + host)
        """
    )
    (f,) = result.findings
    assert f.rule_id == "HS-CMDI-001"
    assert f.vuln_class == "cmdi"
    assert f.function == "Api.run"
    assert f.sink == 'os.system("ping " + host)'
    assert (f.location.start_line, f.location.start_column) == (6, 9)
    assert f.location.end_column == 9 + len(f.sink)
    assert f.sources == ("hackscan",)
    assert f.evidence[0].producer == "ast"


@pytest.mark.parametrize(
    "literal",
    ['"*x*"', r'"\"x\""'],
)
def test_secret_literal_does_not_change_unrelated_rule_words(literal):
    source = f'password = {literal}\nimport os\ndef run(cmd):\n    os.system("ls " + cmd)\n'
    (finding,) = scan(source).findings
    assert "executed" in finding.message
    assert "executed" in finding.evidence[0].message
    assert "e*ecuted" not in finding.message


def test_escaped_secret_quoted_in_rule_message_is_masked():
    raw = r'"\"x\""'
    source = f"import os\ndef run(cmd):\n    os.system(api_token := {raw} + cmd)\n"
    (finding,) = scan(source).findings
    assert raw not in finding.message
    assert "*" * len(raw) in finding.message
    assert "executed" in finding.message
    assert finding.message in finding.evidence[0].message


def test_multiline_secret_quoted_in_rule_message_is_masked_as_one_span():
    source = (
        "import os\ndef run(cmd):\n"
        '    os.system(api_token := """*x*\nquoted \\"value\\"\nlast""" + cmd)\n'
    )
    (finding,) = scan(source).findings
    raw = '"""*x*\nquoted \\"value\\"\nlast"""'
    masked = "".join("*" if char != "\n" else char for char in raw)
    assert raw not in finding.message
    assert masked in finding.message
    assert "executed" in finding.message
    assert finding.message in finding.evidence[0].message


def test_columns_are_characters_not_bytes():
    result = scan('x = "é€"; eval(x + y)\n')
    (f,) = result.findings
    assert f.location.start_column == len('x = "é€"; ') + 1


def test_nested_function_and_lambda_qualnames():
    result = scan(
        """
        def outer(a):
            def inner(b):
                return eval(b)
            f = lambda c: eval(c)
            return inner, f
        """
    )
    assert sorted(f.function for f in result.findings) == [
        "outer.<locals>.<lambda>",
        "outer.<locals>.inner",
    ]


def test_parse_error_is_reported_not_raised():
    result = scan("def broken(:\n")
    assert result.findings == []
    assert "cannot parse" in result.errors[0]


def test_unreadable_file_is_reported(tmp_path: Path):
    bad = tmp_path / "latin1.py"
    bad.write_bytes(b"x = '\xff'\n")
    result = analyze_file(bad, tmp_path, builtin_plugins())
    assert "cannot read" in result.errors[0]


def test_broken_rule_does_not_abort_scan():
    class Boom(RulePlugin):
        rule_id = "X-BOOM"
        name = "boom"
        description = "always fails"
        severity = Severity.LOW

        def check(self, node, ctx):
            raise RuntimeError("kaboom")

    result = analyze_source("eval(x)\n", "a.py", [Boom(), *builtin_plugins()])
    assert [f.rule_id for f in result.findings] == ["HS-CODEI-001"]
    assert "X-BOOM failed: kaboom" in result.errors[0]


def test_ids_stable_when_code_shifts():
    code = "def f(q):\n    eval(q)\n"
    (a,) = assign_ids(scan(code).findings)
    (b,) = assign_ids(scan("import os\n\n\n" + code).findings)
    assert a.id == b.id


def test_nested_eval_survives_dedupe():
    findings = scan("def f(x):\n    return eval(eval(x))\n").findings
    assert len(merge_findings(findings)) == 2


def test_user_plugin_loading(tmp_path: Path):
    (tmp_path / "pickle_rule.py").write_text(
        textwrap.dedent(
            """
            import ast
            from hackscan.core.models import Severity
            from hackscan.plugins import Match, RulePlugin

            class PickleLoads(RulePlugin):
                rule_id = "ACME-PICKLE-001"
                name = "pickle-loads"
                description = "pickle.loads on untrusted data"
                severity = Severity.HIGH
                cwe = ("CWE-502",)

                def check(self, node, ctx):
                    if ctx.call_name(node) == "pickle.loads":
                        yield Match(node, "pickle.loads call")
            """
        )
    )
    plugins = resolve_plugins(tmp_path)
    result = analyze_source("import pickle\npickle.loads(blob)\n", "a.py", plugins)
    (f,) = result.findings
    assert f.rule_id == "ACME-PICKLE-001"
    assert f.vuln_class == "other:CWE-502"


def test_user_plugin_cannot_use_reserved_prefix(tmp_path: Path):
    (tmp_path / "bad.py").write_text(
        textwrap.dedent(
            """
            from hackscan.core.models import Severity
            from hackscan.plugins import RulePlugin

            class Fake(RulePlugin):
                rule_id = "HS-FAKE-001"
                name = "fake"
                description = "x"
                severity = Severity.LOW

                def check(self, node, ctx):
                    return []
            """
        )
    )
    with pytest.raises(PluginError, match="reserved"):
        load_plugins(tmp_path)


def test_plugin_import_error_names_file(tmp_path: Path):
    (tmp_path / "broken.py").write_text("raise ImportError('nope')\n")
    with pytest.raises(PluginError, match="broken.py"):
        load_plugins(tmp_path)


def test_match_confidence_override():
    class Fixed(RulePlugin):
        rule_id = "X-FIXED"
        name = "fixed"
        description = "x"
        severity = Severity.LOW
        node_types = (ast.Name,)

        def check(self, node, ctx):
            yield Match(node, "name", confidence=12)

    (f,) = analyze_source("x\n", "a.py", [Fixed()]).findings
    assert f.confidence == 12


def test_decorator_sink_attributed_to_enclosing_function():
    result = scan(
        """
        def outer(src):
            @deco(eval(src))
            def inner():
                pass
        """
    )
    (f,) = result.findings
    assert f.function == "outer"


def test_declared_source_encoding_is_honored(tmp_path: Path):
    path = tmp_path / "legacy.py"
    path.write_bytes("# -*- coding: latin-1 -*-\nx = 'café'\neval(y)\n".encode("latin-1"))
    result = analyze_file(path, tmp_path, builtin_plugins())
    assert not result.errors
    assert [f.rule_id for f in result.findings] == ["HS-CODEI-001"]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("rule_id = ''", "rule_id must be a non-empty string"),
        ("severity = 'high'", "severity must be a hackscan Severity"),
        ("node_types = ast.Call", "node_types must be a tuple"),
        ("node_types = (str,)", "node_types must be a tuple"),
        ("cwe = 'CWE-1'", "cwe must be a tuple"),
        ("default_confidence = 500", "default_confidence"),
    ],
)
def test_malformed_plugin_attributes_rejected(tmp_path: Path, body: str, message: str):
    (tmp_path / "p.py").write_text(
        textwrap.dedent(
            f"""
            import ast
            from hackscan.core.models import Severity
            from hackscan.plugins import RulePlugin

            class P(RulePlugin):
                rule_id = "ACME-1"
                name = "p"
                description = "d"
                severity = Severity.LOW
                {body}

                def check(self, node, ctx):
                    return []
            """
        )
    )
    with pytest.raises(PluginError, match=message):
        load_plugins(tmp_path)


def test_bad_match_node_is_reported_not_raised():
    class BadMatch(RulePlugin):
        rule_id = "X-BAD"
        name = "bad"
        description = "x"
        severity = Severity.LOW

        def check(self, node, ctx):
            yield Match("not a node", "oops")  # type: ignore[arg-type]

    result = analyze_source("eval(x)\n", "a.py", [BadMatch(), *builtin_plugins()])
    assert [f.rule_id for f in result.findings] == ["HS-CODEI-001"]
    assert "X-BAD returned a bad match" in result.errors[0]
