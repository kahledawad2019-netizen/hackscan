from __future__ import annotations

import textwrap
from pathlib import Path

from hackscan.config import HackScanConfig
from hackscan.core import pipeline
from hackscan.core.pipeline import scan

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
