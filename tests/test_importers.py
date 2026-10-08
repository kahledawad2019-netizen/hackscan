from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from hackscan.config import HackScanConfig
from hackscan.core.models import Severity, Status
from hackscan.core.pipeline import scan
from hackscan.importers.common import ReportError, SourceIndex, make_region, normalize_path
from hackscan.importers.gitleaks import REDACTED, import_gitleaks, load_gitleaks
from hackscan.importers.runner import collect
from hackscan.importers.sarif import import_sarif, load_sarif

FIXTURES = Path(__file__).parent / "fixtures" / "imports"
PROJECT = FIXTURES / "project"


def _sarif(name: str, label: str | None = None):
    return import_sarif(load_sarif(FIXTURES / name), PROJECT, SourceIndex(PROJECT), label)


def test_bandit_recorded_output():
    result = _sarif("bandit.sarif")
    assert result.tool == "bandit"
    by_rule = {f.rule_id: f for f in result.findings}
    assert set(by_rule) == {"bandit:B105", "bandit:B608", "bandit:B605", "bandit:B324"}
    assert by_rule["bandit:B608"].vuln_class == "sqli"
    assert by_rule["bandit:B605"].vuln_class == "cmdi"
    assert by_rule["bandit:B605"].severity is Severity.HIGH
    assert by_rule["bandit:B605"].confidence == 80  # issue_confidence HIGH
    # Enrichment comes from the parsed file, not the tool's snippet.
    assert by_rule["bandit:B605"].sink == 'os.system("ping -c 1 " + request.args["host"])'
    assert by_rule["bandit:B605"].function == "ping"


def test_semgrep_cwe_tags_and_outside_root():
    result = _sarif("semgrep.sarif")
    assert result.tool == "semgrep"
    classes = sorted(f.vuln_class for f in result.findings)
    assert classes == ["cmdi", "sqli"]
    assert any("outside the scan root" in w for w in result.warnings)
    sqli = next(f for f in result.findings if f.vuln_class == "sqli")
    assert sqli.cwe == ("CWE-89",)
    # Region points inside the f-string; the sink is the enclosing execute() call.
    assert sqli.sink.startswith("db.execute(")


def test_codeql_security_severity_and_base_uri():
    result = _sarif("codeql.sarif")
    assert result.tool == "codeql"
    cmdi = next(f for f in result.findings if f.vuln_class == "cmdi")
    assert cmdi.severity is Severity.CRITICAL  # security-severity 9.8
    assert cmdi.location.path == "app.py"  # foreign %SRCROOT% resolved relative to scan root
    assert cmdi.location.end_line == 20  # missing endLine -> start line


def test_label_overrides_driver_name():
    assert _sarif("codeql.sarif", label="semgrep").tool == "semgrep"


def test_gitleaks_redacts_secret():
    result = import_gitleaks(
        load_gitleaks(FIXTURES / "gitleaks.json"), PROJECT, SourceIndex(PROJECT)
    )
    (f,) = result.findings
    assert f.vuln_class == "secret"
    assert f.rule_id == "gitleaks:generic-api-key"
    secret = json.loads((FIXTURES / "gitleaks.json").read_text())[0]["Secret"]
    assert secret not in f.snippet and REDACTED in f.snippet
    assert secret not in json.dumps(f.to_dict())


@pytest.mark.parametrize(
    "content",
    ["not json", '{"no": "runs"}', "[1, 2]"],
)
def test_malformed_sarif_raises_report_error(tmp_path: Path, content: str):
    bad = tmp_path / "bad.sarif"
    bad.write_text(content)
    with pytest.raises(ReportError):
        load_sarif(bad)


def test_malformed_result_is_skipped_with_warning(tmp_path: Path):
    data = load_sarif(FIXTURES / "codeql.sarif")
    data["runs"][0]["results"].append({"ruleId": "x", "locations": [{"physicalLocation": 5}]})
    data["runs"][0]["results"].append({"ruleId": "y"})
    result = import_sarif(data, PROJECT, SourceIndex(PROJECT))
    assert len(result.findings) == 2
    assert len(result.warnings) == 2


def test_gitleaks_rejects_non_array(tmp_path: Path):
    bad = tmp_path / "g.json"
    bad.write_text('{"a": 1}')
    with pytest.raises(ReportError):
        load_gitleaks(bad)


def test_normalize_path_variants(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    assert normalize_path("pkg/a.py", tmp_path) == "pkg/a.py"
    assert normalize_path((tmp_path / "pkg" / "a.py").as_uri(), tmp_path) == "pkg/a.py"
    assert normalize_path("pkg%2Fa.py", tmp_path) == "pkg/a.py"
    assert normalize_path("../elsewhere.py", tmp_path) is None


def test_make_region_normalization():
    r = make_region("a.py", 5, None, None, 9)
    assert (r.start_line, r.end_line, r.start_column, r.end_column) == (5, 5, 1, None)
    r = make_region("a.py", 0, 0, 0, 0)
    assert (r.start_line, r.start_column, r.end_column) == (1, 1, None)
    r = make_region("a.py", 3, 10, 3, 4)  # reversed columns -> whole line end
    assert r.end_column is None


def test_missing_tool_is_a_warning_not_an_error(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    results = collect(PROJECT, PROJECT, ("semgrep",), (), timeout=5)
    assert results.findings == []
    assert results.runs[0].status == "missing"
    assert "not found on PATH" in results.warnings[0]


def test_byo_import_failure_is_reported(tmp_path: Path):
    bad = tmp_path / "x.sarif"
    bad.write_text("{")
    results = collect(PROJECT, PROJECT, (), (("codeql", bad),), timeout=5)
    assert results.runs[0].status == "failed"
    assert results.warnings


def test_cross_tool_dedupe_in_full_scan():
    config = HackScanConfig(
        imports=(
            ("bandit", FIXTURES / "bandit.sarif"),
            ("semgrep", FIXTURES / "semgrep.sarif"),
            ("codeql", FIXTURES / "codeql.sarif"),
            ("gitleaks", FIXTURES / "gitleaks.json"),
        )
    )
    result = scan(PROJECT, config)
    by_class: dict[str, list] = {}
    for f in result.findings:
        by_class.setdefault(f.vuln_class, []).append(f)
    (sqli,) = by_class["sqli"]
    assert sqli.rule_id == "HS-SQLI-001"  # own engine is primary
    assert set(sqli.sources) == {"hackscan", "bandit", "semgrep", "codeql"}
    assert sqli.status is Status.CONFIRMED
    (cmdi,) = by_class["cmdi"]
    assert set(cmdi.sources) == {"hackscan", "bandit", "semgrep", "codeql"}
    assert cmdi.severity is Severity.CRITICAL  # max across tools (CodeQL 9.8)
    secrets = by_class["secret"]
    assert {s for f in secrets for s in f.sources} == {"bandit", "gitleaks"}
    assert len({f.id for f in result.findings}) == len(result.findings)
