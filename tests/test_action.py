from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml
from click.testing import CliRunner

from hackscan.cli import main

ROOT = Path(__file__).parent.parent
CORPUS = Path(__file__).parent / "corpus"
SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)
UNTRUSTED = re.compile(r"\$\{\{\s*(inputs|github\.event)")


def load(relative: str):
    return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def action():
    return load("action.yml")


def steps(action) -> dict[str, dict]:
    return {
        step.get("id") or step.get("name") or step["uses"]: step for step in action["runs"]["steps"]
    }


def test_action_inputs_and_defaults(action):
    defaults = {name: spec.get("default") for name, spec in action["inputs"].items()}
    assert defaults == {
        "path": ".",
        "version": "",
        "fail-on": "high",
        "args": "",
        "sarif-file": "hackscan.sarif",
        "upload-sarif": "true",
    }
    assert not any(spec.get("required") for spec in action["inputs"].values())
    assert set(action["outputs"]) == {"sarif-file", "exit-code"}
    assert action["runs"]["using"] == "composite"


def test_run_scripts_never_interpolate_untrusted_expressions(action):
    workflow = load(".github/workflows/hackscan.yml")
    scripts = [step["run"] for step in action["runs"]["steps"] if "run" in step]
    scripts += [s["run"] for job in workflow["jobs"].values() for s in job["steps"] if "run" in s]
    assert scripts
    for script in scripts:
        assert not UNTRUSTED.search(script), script


def test_upload_always_runs_but_only_with_a_written_report(action):
    upload = steps(action)["Upload SARIF"]
    assert upload["uses"].startswith("github/codeql-action/upload-sarif@")
    assert "always()" in upload["if"]
    assert "inputs.upload-sarif == 'true'" in upload["if"]
    assert "sarif-written == 'true'" in upload["if"]
    assert upload["with"]["category"] == "hackscan"
    apply = steps(action)["Apply scan result"]
    assert "always()" in apply["if"]
    names = [step.get("name") for step in action["runs"]["steps"]]
    assert names.index("Upload SARIF") < names.index("Apply scan result")


def test_scan_command_uses_existing_cli_options(action):
    script = steps(action)["scan"]["run"]
    scan = main.commands["scan"]
    options = {opt for param in scan.params for opt in getattr(param, "opts", [])}
    command = script.split("hackscan scan", 1)[1].split("|| code", 1)[0]
    threshold = re.search(r"threshold=\((-[^)]+)\)", script).group(1)
    used = set(re.findall(r"(?<![\w-])(--?[a-z][\w-]*)", command + threshold))
    assert used <= options, used - options
    assert {"--format", "--sarif-omit-suppressed", "-o", "--fail-on"} <= used
    # The only unquoted expansion ($HACKSCAN_ARGS) must not glob.
    assert script.index("set -f") < script.index("$HACKSCAN_ARGS")


def test_pre_commit_hook_invokes_real_command():
    (hook,) = load(".pre-commit-hooks.yaml")
    assert hook["id"] == "hackscan"
    assert hook["language"] == "python"
    assert hook["pass_filenames"] is False
    assert hook["require_serial"] is True
    program, command = hook["entry"].split()
    assert program == "hackscan"
    scan = main.commands[command]
    ctx = scan.make_context("scan", list(hook["args"]))
    assert ctx.params["path"] == Path(".")
    assert ctx.params["fail_on"] == "high"


def test_dogfood_workflow_uses_local_action_with_least_privilege():
    workflow = load(".github/workflows/hackscan.yml")
    assert workflow["permissions"] == {"contents": "read", "security-events": "write"}
    (job,) = workflow["jobs"].values()
    local = [step for step in job["steps"] if step.get("uses") == "./"]
    assert len(local) == 1
    assert local[0]["with"]["path"] == "src"
    assert local[0]["with"]["fail-on"] == "high"
    assert "head.repo.full_name == github.repository" in local[0]["with"]["upload-sarif"]


def test_threshold_hit_still_writes_valid_sarif(tmp_path):
    out = tmp_path / "corpus.sarif"
    args = ["scan", str(CORPUS), "--format", "sarif", "--sarif-omit-suppressed"]
    result = CliRunner().invoke(main, [*args, "-o", str(out), "--fail-on", "high"])
    assert result.exit_code == 1, result.output
    log = json.loads(out.read_text(encoding="utf-8"))
    jsonschema.Draft4Validator(SCHEMA).validate(log)
    assert log["runs"][0]["results"]


def _bash() -> str | None:
    bash = shutil.which("bash")
    if bash is None or "system32" in bash.lower():  # WSL launcher, not a POSIX shell here
        return None
    return bash


def run_scan_step(action, tmp_path, **inputs) -> dict[str, str]:
    bash = _bash()
    if bash is None:
        pytest.skip("bash is not available")
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": os.pathsep.join(
            [*inputs.get("bin", []), str(Path(sys.executable).parent), os.environ.get("PATH", "")]
        ),
        "GITHUB_OUTPUT": output.as_posix(),
        "HACKSCAN_PATH": inputs.get("path", "."),
        "HACKSCAN_FAIL_ON": inputs.get("fail_on", "high"),
        "HACKSCAN_ARGS": inputs.get("args", ""),
        "HACKSCAN_SARIF_FILE": inputs.get("sarif_file", (tmp_path / "out.sarif").as_posix()),
    }
    env.pop("HACKSCAN_CONFIG", None)
    script = steps(action)["scan"]["run"]
    subprocess.run([bash, "-e", "-c", script], cwd=tmp_path, env=env, check=True, timeout=120)
    lines = output.read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


def test_scan_step_records_threshold_hit_without_failing_the_step(action, tmp_path):
    shutil.copytree(CORPUS / "sqli", tmp_path / "code")
    outputs = run_scan_step(action, tmp_path, path="code")
    assert outputs["exit-code"] == "1"
    assert outputs["sarif-written"] == "true"
    jsonschema.Draft4Validator(SCHEMA).validate(
        json.loads(Path(outputs["sarif-file"]).read_text(encoding="utf-8"))
    )


def test_scan_step_empty_fail_on_disables_threshold(action, tmp_path):
    shutil.copytree(CORPUS / "sqli", tmp_path / "code")
    (tmp_path / ".hackscan.yml").write_text("fail-on: low\n", encoding="utf-8")
    outputs = run_scan_step(action, tmp_path, path="code", fail_on="")
    assert outputs["exit-code"] == "0"


def test_scan_step_empty_fail_on_keeps_a_crash_failing(action, tmp_path):
    # A Python crash exits 1, like a threshold hit; it must not be turned into a pass.
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "hackscan").write_text("#!/bin/sh\necho Traceback >&2\nexit 1\n", encoding="utf-8")
    (fake / "hackscan").chmod(0o755)
    (tmp_path / "code").mkdir()
    outputs = run_scan_step(action, tmp_path, path="code", fail_on="", bin=[fake.as_posix()])
    assert outputs["exit-code"] == "1"
    assert outputs["sarif-written"] == "false"


def test_scan_step_treats_inputs_as_data(action, tmp_path):
    (tmp_path / "code").mkdir()
    (tmp_path / "code" / "ok.py").write_text("x = 1\n", encoding="utf-8")
    marker = tmp_path / "pwned"
    outputs = run_scan_step(action, tmp_path, path=f"code; touch {marker.as_posix()}")
    assert not marker.exists()
    assert outputs["exit-code"] == "2"
    assert outputs["sarif-written"] == "false"


@pytest.mark.skipif(sys.platform == "win32", reason="Click expands wildcards itself on Windows")
def test_scan_step_args_are_split_but_not_globbed(action, tmp_path):
    shutil.copytree(CORPUS / "sqli", tmp_path / "code")
    outputs = run_scan_step(action, tmp_path, path="code", args="--ignore * --severity critical")
    # "*" reaching HackScan literally ignores every file; globbing would pass file names instead.
    assert outputs["exit-code"] == "0"
    log = json.loads(Path(outputs["sarif-file"]).read_text(encoding="utf-8"))
    assert log["runs"][0]["results"] == []
