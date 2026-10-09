from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from hackscan import __version__
from hackscan.cli import main

CORPUS = Path(__file__).parent / "corpus"
FRAMEWORKS = CORPUS / "frameworks"
IMPORTS = Path(__file__).parent / "fixtures" / "imports"


def run(*args: str):
    return CliRunner().invoke(main, list(args))


def test_version():
    result = run("--version")
    assert result.exit_code == 0
    assert __version__ in result.output


def test_text_scan_reports_confirmed_findings():
    result = run("scan", str(FRAMEWORKS))
    assert result.exit_code == 0
    assert "confirmed" in result.output
    assert "Untrusted" in result.output
    assert "Summary:" in result.output
    assert "suppressed hidden" in result.output


@pytest.mark.parametrize(
    ("args", "code"),
    [
        (["--fail-on", "high"], 1),
        (["--fail-on", "critical"], 0),  # no critical findings in the framework corpus
        (["--fail-on", "low", "--min-confidence", "101"], 2),  # invalid value: usage error
    ],
)
def test_fail_on_exit_codes(args: list[str], code: int):
    assert run("scan", str(FRAMEWORKS), *args).exit_code == code


def test_fail_on_ignores_suppressed(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\ncmd = 'ls'\nos.system(cmd)\n")
    assert run("scan", str(tmp_path), "--fail-on", "low").exit_code == 0


def test_json_output_and_filters():
    data = json.loads(run("scan", str(FRAMEWORKS), "--format", "json", "--severity", "high").output)
    assert data["tool"]["name"] == "hackscan"
    assert data["findings"]
    assert all(f["severity"] in {"high", "critical"} for f in data["findings"])
    assert all(f["status"] != "suppressed" for f in data["findings"])
    shown = json.loads(run("scan", str(FRAMEWORKS), "--format", "json", "--show-suppressed").output)
    assert any(f["status"] == "suppressed" for f in shown["findings"])


def test_min_confidence_filter():
    data = json.loads(run("scan", str(CORPUS), "--format", "json", "--min-confidence", "90").output)
    assert data["findings"]
    assert all(f["confidence"] >= 90 for f in data["findings"])


def test_sarif_output_file(tmp_path: Path):
    out = tmp_path / "out.sarif"
    result = run("scan", str(FRAMEWORKS), "--format", "sarif", "-o", str(out))
    assert result.exit_code == 0
    log = json.loads(out.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    assert any(r.get("suppressions") for r in log["runs"][0]["results"])


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
@pytest.mark.parametrize(
    "source,secret",
    [
        (
            'import os\nhandler = lambda cmd, token="lambda-secret-222": os.system(cmd)\n',
            "lambda-secret-222",
        ),
        (
            "import os\ndef f(cmd, password=(\n"
            '    "multiline-secret-222"\n)):\n    os.system(cmd)\n',
            "multiline-secret-222",
        ),
        (
            'import os\ndef f(cmd):\n    os.system(api_token := "correcthorsebat" + cmd)\n',
            "correcthorsebat",
        ),
    ],
)
def test_secret_defaults_and_rule_messages_do_not_leak_in_output(
    tmp_path: Path, fmt: str, source: str, secret: str
):
    path = tmp_path / "secret.py"
    path.write_text(source, encoding="utf-8")
    result = run("scan", str(path), "--format", fmt)
    assert result.exit_code == 0, result.output
    assert "HS-CMDI-001" in result.output
    assert secret not in result.output


def test_ignore_glob(tmp_path: Path):
    (tmp_path / "keep.py").write_text("eval(input())\n")
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("eval(input())\n")
    data = json.loads(run("scan", str(tmp_path), "--format", "json", "--ignore", "legacy").output)
    assert [f["location"]["path"] for f in data["findings"]] == ["keep.py"]


def test_import_option_and_bad_import():
    report = IMPORTS / "codeql.sarif"
    result = run(
        "scan", str(IMPORTS / "project"), "--format", "json", "--import", f"codeql={report}"
    )
    data = json.loads(result.output)
    assert any("codeql" in f["sources"] for f in data["findings"])
    assert run("scan", str(IMPORTS / "project"), "--import", "nope=x").exit_code == 2


def test_with_missing_tool_warns_and_strict_fails(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    (tmp_path / "a.py").write_text("x = 1\n")
    lenient = run("scan", str(tmp_path), "--with", "semgrep")
    assert lenient.exit_code == 0
    assert "not found on PATH" in lenient.output
    assert run("scan", str(tmp_path), "--with", "semgrep", "--strict-tools").exit_code == 2


def test_unknown_tool_is_usage_error(tmp_path: Path):
    assert run("scan", str(tmp_path), "--with", "nmap").exit_code == 2


def test_config_file_is_discovered(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text("ignore: [skip]\nfail-on: high\n")
    (tmp_path / "skip").mkdir()
    (tmp_path / "skip" / "x.py").write_text("eval(input())\n")
    assert run("scan", str(tmp_path)).exit_code == 0
    (tmp_path / "y.py").write_text("eval(input())\n")
    assert run("scan", str(tmp_path)).exit_code == 1


def test_bad_config_is_usage_error(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text("severity: extreme\n")
    result = run("scan", str(tmp_path))
    assert result.exit_code == 2
    assert "severity" in result.output


def test_no_taint_leaves_candidates(tmp_path: Path):
    (tmp_path / "a.py").write_text("import os\nos.system(input())\n")
    data = json.loads(run("scan", str(tmp_path), "--format", "json", "--no-taint").output)
    assert [f["status"] for f in data["findings"]] == ["candidate"]


def test_single_file_target(tmp_path: Path):
    target = tmp_path / "one.py"
    target.write_text("eval(input())\n")
    data = json.loads(run("scan", str(target), "--format", "json").output)
    assert data["stats"]["files_scanned"] == 1


def test_quiet_and_rules_command():
    quiet = run("scan", str(FRAMEWORKS), "-q")
    assert "Summary" not in quiet.output and "HackScan" not in quiet.output
    assert "HS-SQLI-001" in run("rules").output


def test_plugins_option(tmp_path: Path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "p.py").write_text(
        textwrap.dedent(
            """
            from hackscan.core.models import Severity
            from hackscan.plugins import Match, RulePlugin

            class Pickle(RulePlugin):
                rule_id = "ACME-1"
                name = "pickle"
                description = "pickle.loads"
                severity = Severity.HIGH
                cwe = ("CWE-502",)

                def check(self, node, ctx):
                    if ctx.call_name(node) == "pickle.loads":
                        yield Match(node, "pickle")
            """
        )
    )
    (tmp_path / "a.py").write_text("import pickle\npickle.loads(b)\n")
    out = run("scan", str(tmp_path), "--format", "json", "--plugins", str(plugins)).output
    assert [f["rule_id"] for f in json.loads(out)["findings"]] == ["ACME-1"]


def test_plugin_constructor_error_exits_2_not_1(tmp_path: Path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "p.py").write_text(
        textwrap.dedent(
            """
            from hackscan.core.models import Severity
            from hackscan.plugins import RulePlugin

            class Broken(RulePlugin):
                rule_id = "ACME-2"
                name = "broken"
                description = "broken"
                severity = Severity.HIGH
                cwe = ("CWE-502",)

                def __init__(self):
                    raise RuntimeError("boom")

                def check(self, node, ctx):
                    yield from ()
            """
        )
    )
    (tmp_path / "a.py").write_text("x = 1\n")
    result = run("scan", str(tmp_path), "--plugins", str(plugins))
    assert result.exit_code == 2
    assert "error creating plugin p.py: boom" in result.output


@pytest.mark.parametrize(("config", "expected"), [("fail-on: low\n", 0), ("", 0)])
def test_fail_on_never_overrides_config(tmp_path: Path, config: str, expected: int):
    shutil.copytree(CORPUS / "sqli", tmp_path / "code")
    (tmp_path / ".hackscan.yml").write_text(config)
    assert run("scan", str(tmp_path / "code"), "--fail-on", "never").exit_code == expected
    if config:
        assert run("scan", str(tmp_path / "code")).exit_code == 1


def test_parallel_and_serial_scans_agree():
    serial = json.loads(run("scan", str(CORPUS), "--format", "json", "--jobs", "1").output)
    parallel = json.loads(run("scan", str(CORPUS), "--format", "json", "--jobs", "2").output)
    assert serial["findings"] == parallel["findings"]


def test_incomplete_scan_exits_2_and_is_marked(tmp_path: Path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "broken.py").write_text("def x(:\n")
    result = run("scan", str(tmp_path))
    assert result.exit_code == 2
    assert "INCOMPLETE" in result.output and "broken.py" in result.output
    # Incomplete wins over --fail-on findings: the result is not a trustworthy verdict.
    (tmp_path / "vuln.py").write_text("eval(input())\n")
    assert run("scan", str(tmp_path), "--fail-on", "low").exit_code == 2
    assert run("scan", str(tmp_path), "--allow-incomplete").exit_code == 0
    assert run("scan", str(tmp_path), "--allow-incomplete", "--fail-on", "low").exit_code == 1


def test_incomplete_scan_sarif_execution_unsuccessful(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def x(:\n")
    out = tmp_path / "r.sarif"
    run("scan", str(tmp_path), "--format", "sarif", "-o", str(out), "--allow-incomplete")
    invocation = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert any(
        "broken.py" in n["message"]["text"] for n in invocation["toolExecutionNotifications"]
    )


def test_allow_incomplete_from_config(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text("allow-incomplete: true\n")
    (tmp_path / "broken.py").write_text("def x(:\n")
    assert run("scan", str(tmp_path)).exit_code == 0


def test_output_refuses_to_overwrite_source(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text("eval(input())\n")
    result = run("scan", str(target), "-o", str(target))
    assert result.exit_code == 2
    assert target.read_text() == "eval(input())\n"
    assert run("scan", str(tmp_path), "-o", str(tmp_path / "other.py")).exit_code == 2


def test_output_creates_parent_directories(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    out = tmp_path / "reports" / "deep" / "r.json"
    assert run("scan", str(tmp_path), "--format", "json", "-o", str(out)).exit_code == 0
    assert out.is_file()


def test_sarif_omit_suppressed(tmp_path: Path):
    out = tmp_path / "r.sarif"
    run("scan", str(FRAMEWORKS), "--format", "sarif", "--sarif-omit-suppressed", "-o", str(out))
    results = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert results and not any(r.get("suppressions") for r in results)


def test_config_rejects_field_style_keys(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text("with-tools: [gitleaks]\n")
    result = run("scan", str(tmp_path))
    assert result.exit_code == 2 and "unknown option" in result.output


def test_failed_import_makes_scan_incomplete(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = tmp_path / "notes.md"
    bad.write_text("# not sarif\n")
    result = run("scan", str(tmp_path), "--import", f"sarif={bad}")
    assert result.exit_code == 2
    assert "INCOMPLETE" in result.output
    assert (
        run("scan", str(tmp_path), "--import", f"sarif={bad}", "--allow-incomplete").exit_code == 0
    )


@pytest.mark.parametrize("name", ["pyproject.toml", "release.yml", "notes.json"])
def test_output_never_overwrites_non_report_files(tmp_path: Path, name: str):
    (tmp_path / "a.py").write_text("x = 1\n")
    victim = tmp_path / name
    victim.write_text("[project]\nname = 'keep me'\n")
    assert run("scan", str(tmp_path), "--format", "json", "-o", str(victim)).exit_code == 2
    assert "keep me" in victim.read_text()


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_output_may_overwrite_previous_report(tmp_path: Path, fmt: str):
    (tmp_path / "a.py").write_text("x = 1\n")
    out = tmp_path / f"report.{fmt}"
    assert run("scan", str(tmp_path), "--format", fmt, "-o", str(out)).exit_code == 0
    assert run("scan", str(tmp_path), "--format", fmt, "-o", str(out)).exit_code == 0
