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
