from __future__ import annotations

import json
import textwrap
from dataclasses import replace
from pathlib import Path

import pytest

from hackscan.analyzers.llm_pass import LLMReport
from hackscan.config import HackScanConfig
from hackscan.core import pipeline
from hackscan.core.models import Fix, FixEdit
from hackscan.core.pipeline import scan
from hackscan.plugins.loader import builtin_plugins
from hackscan.sarif.generator import export_sarif

CORPUS = Path(__file__).parent / "corpus"

PLUGIN = textwrap.dedent(
    """
    from hackscan.core.models import Severity
    from hackscan.plugins import Match, RulePlugin

    class Pickle(RulePlugin):
        rule_id = "ACME-1"
        name = "pickle"
        description = "pickle.loads"
        severity = Severity.HIGH

        def check(self, node, ctx):
            if ctx.call_name(node) == "pickle.loads":
                yield Match(node, "pickle")
    """
)


def test_process_pool_matches_serial(monkeypatch):
    monkeypatch.setattr(pipeline, "PARALLEL_THRESHOLD", 0)
    serial = scan(CORPUS, HackScanConfig(jobs=1))
    parallel = scan(CORPUS, HackScanConfig(jobs=3))
    assert [f.to_dict() for f in serial.findings] == [f.to_dict() for f in parallel.findings]
    assert serial.files_scanned == parallel.files_scanned > 5


def test_process_pool_loads_user_plugins(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pipeline, "PARALLEL_THRESHOLD", 0)
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "p.py").write_text(PLUGIN)
    project = tmp_path / "project"
    project.mkdir()
    for i in range(4):
        (project / f"m{i}.py").write_text("import pickle\npickle.loads(b)\n")
    result = scan(project, HackScanConfig(jobs=2, plugins=plugins))
    assert [f.rule_id for f in result.findings] == ["ACME-1"] * 4


def test_unparseable_files_are_reported_not_fatal(tmp_path: Path):
    (tmp_path / "ok.py").write_text("eval(input())\n")
    (tmp_path / "broken.py").write_text("def x(:\n")
    result = scan(tmp_path, HackScanConfig())
    assert len(result.findings) == 1
    assert any("broken.py" in e and "cannot parse" in e for e in result.errors)


def test_template_fix_containing_known_secret_is_dropped(tmp_path: Path):
    secret = "secret-abc123"
    (tmp_path / "m.py").write_text(
        'import os\napi_token = "secret-abc123"\n'
        'def run(x):\n    os.system(f"printf secret-abc123 {x}")\n',
        encoding="utf-8",
    )
    result = scan(tmp_path, HackScanConfig())
    assert secret in result.secrets
    assert result.findings
    assert all(f.fix is None for f in result.findings)
    dumped = json.dumps([f.to_dict() for f in result.findings])
    dumped += json.dumps(export_sarif(result, builtin_plugins()))
    assert secret not in dumped


def test_function_matching_file_secret_is_redacted_in_json_and_sarif(tmp_path: Path):
    from hackscan.cli import _json

    (tmp_path / "m.py").write_text(
        'import os\napi_token = "hunter2"\ndef hunter2(cmd):\n    os.system(cmd)\n',
        encoding="utf-8",
    )
    config = HackScanConfig()
    result = scan(tmp_path, config)
    assert result.findings
    assert result.findings[0].function == "<REDACTED>"
    for output in (
        json.dumps(_json(result, result.findings)),
        json.dumps(export_sarif(result, builtin_plugins())),
    ):
        assert "hunter2" not in output


@pytest.mark.parametrize("secret_field", ["description", "replacement"])
def test_llm_fix_containing_known_secret_is_dropped(tmp_path: Path, monkeypatch, secret_field):
    secret = "secret-abc123"
    (tmp_path / "m.py").write_text(
        'import os\napi_token = "secret-abc123"\ndef run(x):\n    os.system(f"printf safe {x}")\n',
        encoding="utf-8",
    )

    def triage_with_secret_fix(findings, _index, _config, **_kwargs):
        fix = Fix(
            f"Apply {secret if secret_field == 'description' else 'safe fix'}",
            (
                FixEdit(
                    findings[0].location,
                    "subprocess.call(['printf', '"
                    + (secret if secret_field == "replacement" else "safe")
                    + "', x])",
                ),
            ),
            "llm",
        )
        return LLMReport([replace(findings[0], fix=fix)], [], 1)

    monkeypatch.setattr(pipeline, "triage", triage_with_secret_fix)
    result = scan(tmp_path, HackScanConfig(fixes=False, llm=True))
    assert result.findings[0].fix is None
    dumped = json.dumps([f.to_dict() for f in result.findings])
    dumped += json.dumps(export_sarif(result, builtin_plugins()))
    assert secret not in dumped


def test_short_source_secret_is_redacted_in_imported_output_and_llm(tmp_path: Path, monkeypatch):
    from hackscan.analyzers.llm_pass import LLMConfig, triage
    from hackscan.cli import _text

    secret = "hunter2"
    (tmp_path / "m.py").write_text(
        'import os\napi_token = "hunter2"\ndef run(cmd):\n    os.system(cmd)\n',
        encoding="utf-8",
    )
    report = tmp_path / "report.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [
                            {
                                "ruleId": "B605",
                                "message": {"text": f"credential {secret} reaches this call"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "m.py"},
                                            "region": {"startLine": 4},
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
    requests = []

    def fake_transport(_url, payload, _timeout):
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
            findings, index, LLMConfig(cache_dir=None), transport=fake_transport, **kwargs
        ),
    )
    config = HackScanConfig(imports=(("bandit", report),), llm=True)
    result = scan(tmp_path, config)
    assert requests
    outputs = (
        _text(result, result.findings, config, quiet=True),
        json.dumps([f.to_dict() for f in result.findings]),
        json.dumps(export_sarif(result, builtin_plugins())),
        json.dumps(requests),
    )
    assert all(secret not in output for output in outputs)
    assert "<REDACTED>" in outputs[1]


def test_file_secret_in_sarif_rule_metadata_is_redacted_before_llm(tmp_path: Path, monkeypatch):
    from hackscan.analyzers.llm_pass import LLMConfig, triage
    from hackscan.cli import _json, _text

    (tmp_path / "a.py").write_text(
        'import os\napi_token = "panda"\ndef run(cmd):\n    os.system(cmd)\n',
        encoding="utf-8",
    )
    report = tmp_path / "report.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [
                            {
                                "ruleId": "panda",
                                "message": {"text": "flagged call"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "a.py"},
                                            "region": {"startLine": 4},
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
    requests = []

    def fake_transport(_url, payload, _timeout):
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
            findings, index, LLMConfig(cache_dir=None), transport=fake_transport, **kwargs
        ),
    )
    config = HackScanConfig(imports=(("bandit", report),), llm=True)
    result = scan(tmp_path, config)
    imported = [f for f in result.findings if "bandit" in f.sources]
    assert imported and imported[0].rule_id == "bandit:<REDACTED>"
    sarif = export_sarif(result, builtin_plugins())
    assert any(
        rule["id"] == "bandit:<REDACTED>" for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
    )
    outputs = (
        _text(result, result.findings, config, quiet=False),
        json.dumps(_json(result, result.findings)),
        json.dumps(sarif),
        json.dumps(requests),
    )
    assert requests and all("panda" not in output for output in outputs)


def test_file_secret_in_diagnostics_is_redacted_in_all_formats(tmp_path: Path, monkeypatch):
    from hackscan.cli import _json, _text

    (tmp_path / "a.py").write_text('api_token = "panda"\n', encoding="utf-8")
    report = tmp_path / "report.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [{"ruleId": "panda", "message": {"text": "x"}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    collect = pipeline.collect

    def collect_with_error(*args, **kwargs):
        external = collect(*args, **kwargs)
        external.errors.append("panda caused an import error")
        return external

    monkeypatch.setattr(pipeline, "collect", collect_with_error)
    config = HackScanConfig(imports=(("bandit", report),))
    result = scan(tmp_path, config)
    assert result.warnings and result.errors
    assert "<REDACTED>" in " ".join(result.warnings + result.errors)
    outputs = (
        _text(result, result.findings, config, quiet=False),
        json.dumps(_json(result, result.findings)),
        json.dumps(export_sarif(result, builtin_plugins())),
    )
    assert all("panda" not in output for output in outputs)


def test_short_source_secret_is_scoped_to_its_file(tmp_path: Path):
    (tmp_path / "a.py").write_text('token_type = "Bearer"\n', encoding="utf-8")
    (tmp_path / "b.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    report = tmp_path / "report.sarif"
    report.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {"driver": {"name": "Bandit"}},
                        "results": [
                            {
                                "ruleId": "B605",
                                "message": {"text": "Bearer value reaches this call"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "b.py"},
                                            "region": {"startLine": 1},
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
    assert any(f.location.path == "b.py" and "Bearer" in f.message for f in result.findings)


def test_llm_fix_containing_short_file_secret_is_dropped(tmp_path: Path, monkeypatch):
    secret = "hunter2"
    (tmp_path / "m.py").write_text(
        'import os\napi_token = "hunter2"\ndef run(cmd):\n    os.system(cmd)\n',
        encoding="utf-8",
    )

    def triage_with_secret_fix(findings, _index, _config, **_kwargs):
        fix = Fix(
            "Apply safe rewrite",
            (FixEdit(findings[0].location, f"subprocess.run(['{secret}', cmd])"),),
            "llm",
        )
        return LLMReport([replace(findings[0], fix=fix)], [], 1)

    monkeypatch.setattr(pipeline, "triage", triage_with_secret_fix)
    result = scan(tmp_path, HackScanConfig(fixes=False, llm=True))
    assert result.findings[0].fix is None
