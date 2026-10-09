from __future__ import annotations

import ast
import json
import shutil
from pathlib import Path

import pytest

from hackscan.config import HackScanConfig
from hackscan.core.models import Severity, Status
from hackscan.core.pipeline import scan
from hackscan.core.redact import SECRET_NAME_RE, mask_secret_literals, secret_literal_values
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
    r = make_region("a.py", 3, 10, 3, 4)  # reversed columns -> point at start
    assert r.end_column == 10
    r = make_region("a.py", 3, 10)  # start column but no end -> point, not rest of line
    assert (r.end_line, r.end_column) == (3, 10)


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
    assert results.errors  # an explicitly requested report: the scan is incomplete


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


# -- Codex M3 review regressions ------------------------------------------------------------

SECRET = "hackscan-fake-token-0123456789"


def _project_scan(**kwargs):
    imports = (
        ("bandit", FIXTURES / "bandit.sarif"),
        ("gitleaks", FIXTURES / "gitleaks.json"),
    )
    return scan(PROJECT, HackScanConfig(imports=kwargs.get("imports", imports)))


def test_secret_never_leaks_after_merge_with_bandit():
    from hackscan.plugins.loader import builtin_plugins
    from hackscan.sarif.generator import export_sarif

    result = _project_scan()
    assert SECRET not in json.dumps([f.to_dict() for f in result.findings])
    assert SECRET not in json.dumps(export_sarif(result, builtin_plugins()))


def test_secret_class_literals_redacted_without_gitleaks():
    result = _project_scan(imports=(("bandit", FIXTURES / "bandit.sarif"),))
    secrets = [f for f in result.findings if f.vuln_class == "secret"]
    assert secrets
    assert SECRET not in json.dumps([f.to_dict() for f in secrets])


def test_column_points_from_different_tools_do_not_merge(tmp_path):
    from hackscan.core.dedupe import merge_findings

    (tmp_path / "a.py").write_text("import os\nos.system(a); os.system(b)\n")
    index = SourceIndex(tmp_path)

    def sarif(tool, col):
        return {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool,
                            "rules": [{"id": "r", "properties": {"tags": ["CWE-78"]}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "r",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.py"},
                                        "region": {"startLine": 2, "startColumn": col},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

    a = import_sarif(sarif("Semgrep OSS", 1), tmp_path, index).findings
    b = import_sarif(sarif("CodeQL", 15), tmp_path, index).findings
    assert len(merge_findings([*a, *b])) == 2


def test_imported_findings_obey_default_ignores(tmp_path):
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / "app.py").write_text("x = 1\n")
    report = tmp_path / "r.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Semgrep OSS"}},
                        "results": [
                            {
                                "ruleId": "r",
                                "message": {"text": "m"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": ".venv/lib/a.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    result = scan(tmp_path, HackScanConfig(imports=(("semgrep", report),)))
    assert result.findings == []


def test_remote_file_uri_is_rejected(tmp_path):
    assert normalize_path("file://remote-host/share/app.py", tmp_path) is None
    assert normalize_path(f"file://localhost{(tmp_path / 'a.py').as_uri()[7:]}", tmp_path) == "a.py"


def test_malformed_gitleaks_entry_is_skipped():
    items = load_gitleaks(FIXTURES / "gitleaks.json")
    items.append({**items[0], "StartLine": "n/a"})
    result = import_gitleaks(items, PROJECT, SourceIndex(PROJECT))
    assert len(result.findings) == 1
    assert any("malformed" in w for w in result.warnings)


def test_unquoted_secret_from_other_tool_is_redacted(tmp_path):
    from hackscan.plugins.loader import builtin_plugins
    from hackscan.sarif.generator import export_sarif

    (tmp_path / "settings.py").write_text("DB_PASSWORD = hunter2hunter2  # set in prod\n")
    report = tmp_path / "r.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [
                                    {
                                        "id": "py/hardcoded-credentials",
                                        "properties": {"tags": ["external/cwe/cwe-798"]},
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "py/hardcoded-credentials",
                                "message": {
                                    "text": "Hard-coded credential hunter2hunter2 used here"
                                },
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "settings.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    result = scan(tmp_path, HackScanConfig(imports=(("codeql", report),)))
    (f,) = result.findings
    assert f.vuln_class == "secret"
    dumped = json.dumps([f.to_dict()]) + json.dumps(export_sarif(result, builtin_plugins()))
    assert "hunter2hunter2" not in dumped


def test_known_secret_redacted_from_warnings(tmp_path):
    secret = "s3cr3t-value-in-path"
    report = tmp_path / "g.json"
    report.write_text(
        json.dumps(
            [
                {
                    "File": f"/elsewhere/{secret}/x.py",
                    "StartLine": 1,
                    "Secret": secret,
                    "RuleID": "generic",
                }
            ]
        )
    )
    (tmp_path / "a.py").write_text("x = 1\n")
    result = scan(tmp_path, HackScanConfig(imports=(("gitleaks", report),)))
    assert result.warnings
    assert secret not in " ".join(result.warnings + result.errors)


def test_tool_error_exit_code_is_partial(monkeypatch, tmp_path):
    import subprocess

    from hackscan.importers import runner

    monkeypatch.setattr(shutil, "which", lambda name: name)

    def fake_run(command, **kwargs):
        out = Path(command[command.index("--output") + 1])
        out.write_text((FIXTURES / "semgrep.sarif").read_text(encoding="utf-8"))
        return subprocess.CompletedProcess(command, 2, "", "semgrep: fatal error")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    results = collect(PROJECT, PROJECT, ("semgrep",), (), timeout=5)
    assert results.runs[0].status == "partial"
    assert results.findings  # what it did find is kept
    assert any("error code 2" in w for w in results.warnings)


def test_gitleaks_secrets_in_one_file_keep_distinct_ids(tmp_path):
    (tmp_path / "a.py").write_text("A = 'one-secret-value'\nB = 'two-secret-value'\n")
    report = tmp_path / "g.json"
    report.write_text(
        json.dumps(
            [
                {"File": "a.py", "StartLine": 1, "Secret": "one-secret-value", "RuleID": "generic"},
                {"File": "a.py", "StartLine": 2, "Secret": "two-secret-value", "RuleID": "generic"},
            ]
        )
    )
    result = scan(tmp_path, HackScanConfig(imports=(("gitleaks", report),)))
    assert len({f.id for f in result.findings}) == 2
    assert all("@L" in f.sink for f in result.findings)


def test_tool_snippet_never_restores_a_masked_secret(tmp_path):
    # Codex verify round 3: a SARIF snippet used to win over the masked source line.
    from hackscan.plugins.loader import builtin_plugins
    from hackscan.sarif.generator import export_sarif

    token = "hackscan-fake-token-0123456789"
    (tmp_path / "m.py").write_text(
        # No own finding on this line, so the imported one stands alone (no merge).
        f'import random\n\ndef f():\n    API_TOKEN = "{token}"; return random.random()\n'
    )
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": "m.py"},
            "region": {"startLine": 4, "snippet": {"text": f'API_TOKEN = "{token}"'}},
        }
    }
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "rules": [{"id": "B311"}]}},
                "results": [
                    {"ruleId": "B311", "message": {"text": "random"}, "locations": [location]}
                ],
            }
        ]
    }
    report = tmp_path / "r.sarif"
    report.write_text(json.dumps(sarif))
    result = scan(tmp_path, HackScanConfig(imports=(("bandit", report),)))
    assert any("bandit" in f.sources for f in result.findings)
    dumped = json.dumps([f.to_dict() for f in result.findings])
    dumped += json.dumps(export_sarif(result, builtin_plugins()))
    assert token not in dumped


@pytest.mark.parametrize("as_bytes", [False, True])
def test_source_secret_in_tool_message_is_redacted_before_llm(tmp_path, monkeypatch, as_bytes):
    from hackscan.analyzers.llm_pass import LLMConfig, triage
    from hackscan.core import pipeline
    from hackscan.plugins.loader import builtin_plugins
    from hackscan.sarif.generator import export_sarif

    secret = "bytes-secret-123" if as_bytes else "demo-secret-123"
    literal = f'{"b" if as_bytes else ""}"{secret}"'
    (tmp_path / "m.py").write_text(
        f"import os\n\ndef run(cmd):\n    API_TOKEN = {literal}\n    os.system(cmd)\n",
        encoding="utf-8",
    )
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "rules": [{"id": "B605"}]}},
                "results": [
                    {
                        "ruleId": "B605",
                        "message": {"text": f"API_TOKEN = {literal} reaches this call"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "m.py"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    report = tmp_path / "r.sarif"
    report.write_text(json.dumps(sarif), encoding="utf-8")
    requests = []

    def fake_transport(url, payload, timeout):
        requests.append(payload)
        return {
            "message": {
                "content": json.dumps(
                    {
                        "verdict": "uncertain",
                        "reason": "unclear",
                        "evidence_line": None,
                        "evidence_kind": None,
                        "fixed_call": None,
                    }
                )
            }
        }

    monkeypatch.setattr(
        pipeline,
        "triage",
        lambda findings, index, config, **kwargs: triage(
            findings,
            index,
            LLMConfig(cache_dir=None),
            transport=fake_transport,
            **kwargs,
        ),
    )
    result = scan(tmp_path, HackScanConfig(imports=(("bandit", report),), llm=True))
    dumped = json.dumps([f.to_dict() for f in result.findings])
    dumped += json.dumps(export_sarif(result, builtin_plugins()))
    assert requests
    assert secret not in dumped + json.dumps(requests)


def test_secret_literal_values_cover_joined_multiline_and_fstring_parts():
    tree = ast.parse(
        'API_TOKEN = ("joined-" "secret")\n'
        'PASSWORD = """\n  first-secret\n  second-secret\n"""\n'
        'AUTH_KEY = f"prefix-secret{user}suffix-secret"\n'
        'API_KEY = "abc"\n'
    )
    values = secret_literal_values(tree)
    assert {
        "joined-secret",
        "\n  first-secret\n  second-secret\n",
        "first-secret",
        "second-secret",
        "prefix-secret",
        "suffix-secret",
    } <= values
    assert "abc" not in values


def test_secret_literal_values_decode_bytes_and_limit_partial_pieces():
    tree = ast.parse(
        'api_key = b"\\xffbytes-secret-123"\n'
        'password = f"pre-{value}-suffix-secret"\n'
        'api_token = """small\nlong-secret-123"""\n'
        'access_key = "four"\n'
    )
    values = secret_literal_values(tree)
    assert {"bytes-secret-123", "-suffix-secret", "long-secret-123", "four"} <= values
    assert "pre-" not in values
    assert "small" not in values


def test_partial_secret_pieces_need_eight_characters():
    tree = ast.parse(
        'password = f"pre-{value}-suffix-secret"\napi_token = """small\nlong-secret-123"""\n'
    )
    values = secret_literal_values(tree)
    assert "pre-" not in values
    assert "small" not in values
    assert {"-suffix-secret", "long-secret-123"} <= values


@pytest.mark.parametrize(
    ("name", "secret_named"),
    [
        ("auth", True),
        ("auth_token", True),
        ("authorization", True),
        ("oauth", True),
        ("basic_auth", True),
        ("AUTH_HEADER", True),
        ("api_key", True),
        ("token", True),
        ("secret", True),
        ("password", True),
        ("pwd", True),
        ("credential", True),
        ("author", False),
        ("authors", False),
        ("authority", False),
        ("author_name", False),
        ("authority_code", False),
    ],
)
def test_secret_name_matching_excludes_author_names(name, secret_named):
    assert bool(SECRET_NAME_RE.search(name)) is secret_named


def test_author_assignment_is_not_masked():
    source = 'author = "Jane Q Public"\n'
    tree = ast.parse(source)
    assert mask_secret_literals(source, tree) == source
    assert "Jane Q Public" not in secret_literal_values(tree)


@pytest.mark.parametrize("tool_snippet", [False, True])
def test_unparseable_python_fallback_snippet_is_redacted(tmp_path, tool_snippet):
    secret = "loop-secret-12345"
    (tmp_path / "broken.py").write_text(
        f'for api_token in ("{secret}",):\n    pass\nif (\n', encoding="utf-8"
    )
    region = {"startLine": 1}
    if tool_snippet:
        region["snippet"] = {"text": f'for api_token in ("{secret}",):'}
    report = tmp_path / "r.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [
                            {
                                "ruleId": "B605",
                                "message": {"text": "possible issue"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "broken.py"},
                                            "region": region,
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = scan(tmp_path, HackScanConfig(imports=(("bandit", report),)))
    assert result.findings
    assert secret not in json.dumps([f.to_dict() for f in result.findings])
