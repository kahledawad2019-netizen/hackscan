from __future__ import annotations

from pathlib import Path

import pytest

from hackscan.config import ConfigError, HackScanConfig, discover, load
from hackscan.core.models import Severity
from hackscan.core.pipeline import _is_ignored, discover_files


def test_defaults():
    config = HackScanConfig()
    assert config.severity is Severity.LOW and config.fail_on is None and config.taint


def test_hierarchical_merge(tmp_path: Path):
    project = tmp_path / "project"
    sub = project / "service"
    sub.mkdir(parents=True)
    (project / ".hackscan.yml").write_text("ignore: [vendor]\nseverity: medium\nfail-on: high\n")
    (sub / ".hackscan.yml").write_text("ignore: [generated]\nseverity: low\n")
    assert discover(sub)[-2:] == [project / ".hackscan.yml", sub / ".hackscan.yml"]
    config = load(sub)
    assert config.ignore[-2:] == ("vendor", "generated")
    assert config.severity is Severity.LOW  # nearer file wins
    assert config.fail_on is Severity.HIGH  # inherited


def test_cli_overrides_and_ignore_appends(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text("ignore: [a]\nmin-confidence: 30\n")
    config = load(tmp_path).with_overrides(ignore=("b",), min_confidence=None, jobs=2)
    assert config.ignore[-2:] == ("a", "b")
    assert config.min_confidence == 30
    assert config.jobs == 2


def test_relative_paths_resolve_against_config_file(tmp_path: Path):
    (tmp_path / "rules").mkdir()
    (tmp_path / ".hackscan.yml").write_text(
        "plugins: rules\nimport:\n  codeql: out/results.sarif\nwith: [bandit]\n"
    )
    config = load(tmp_path)
    assert config.plugins == (tmp_path / "rules").resolve()
    assert config.imports == (("codeql", (tmp_path / "out" / "results.sarif").resolve()),)
    assert config.with_tools == ("bandit",)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("severity: extreme", "severity"),
        ("min-confidence: 500", "min-confidence"),
        ("ignore: vendor", "ignore"),
        ("with: [nmap]", "unknown tool"),
        ("import: {pdf: x}", "unknown import format"),
        ("bogus: 1", "unknown option"),
        ("- just a list", "mapping"),
        ("taint: maybe", "taint"),
    ],
)
def test_invalid_config(tmp_path: Path, content: str, message: str):
    (tmp_path / ".hackscan.yml").write_text(content + "\n")
    with pytest.raises(ConfigError, match=message):
        load(tmp_path)


@pytest.mark.parametrize(
    ("path", "patterns", "ignored"),
    [
        ("src/app.py", ("tests/*",), False),
        ("tests/test_a.py", ("tests/*",), True),
        ("pkg/migrations/0001.py", ("**/migrations/**",), True),
        ("pkg/legacy/x.py", ("legacy",), True),
        ("pkg/legacy_ok/x.py", ("legacy",), False),
        ("a/b/gen_pb2.py", ("*_pb2.py",), True),
    ],
)
def test_ignore_patterns(path: str, patterns: tuple[str, ...], ignored: bool):
    assert _is_ignored(path, patterns) is ignored


def test_default_ignores_prune_directories(tmp_path: Path):
    for d in (".venv/lib", "node_modules/x", "src", "pkg.egg-info"):
        (tmp_path / d).mkdir(parents=True)
    for f in (".venv/lib/a.py", "node_modules/x/b.py", "src/c.py", "pkg.egg-info/d.py"):
        (tmp_path / f).write_text("x = 1\n")
    found = [p.relative_to(tmp_path).as_posix() for p in discover_files(tmp_path, tmp_path, ())]
    assert found == ["src/c.py"]
