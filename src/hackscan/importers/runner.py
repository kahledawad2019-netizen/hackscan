"""Run external scanners (`--with`) and load bring-your-own reports (`--import`).

Run mode never fails the scan by default: a missing tool, a timeout or unusable output
becomes a warning and that source is skipped (`--strict-tools` makes it an error).
A non-zero exit code with valid output is accepted (scanners exit 1 on findings).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from hackscan.importers.common import ImportResult, ReportError, SourceIndex
from hackscan.importers.gitleaks import import_gitleaks, load_gitleaks
from hackscan.importers.sarif import import_sarif, load_sarif


@dataclass
class ToolRun:
    tool: str
    status: str  # "ok", "partial", "missing", "failed", "timeout", "imported"
    detail: str = ""
    findings: int = 0


@dataclass
class ExternalResults:
    findings: list = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Requested reports that could not be imported: the scan is incomplete.
    errors: list[str] = field(default_factory=list)
    runs: list[ToolRun] = field(default_factory=list)
    secrets: set[str] = field(default_factory=set)

    def add(self, result: ImportResult, run: ToolRun) -> None:
        self.findings.extend(result.findings)
        self.warnings.extend(result.warnings)
        self.secrets |= result.secrets
        run.findings = len(result.findings)
        self.runs.append(run)


# Exit codes meaning "ran to completion" (1 = findings reported for semgrep/bandit).
OK_EXIT_CODES = {"semgrep": {0, 1}, "bandit": {0, 1}, "gitleaks": {0}}


def _commands(tool: str, target: Path, out: Path) -> list[str]:
    if tool == "semgrep":
        return [
            "semgrep",
            "scan",
            "--config",
            "p/python",
            "--sarif",
            "--output",
            str(out),
            "--quiet",
            "--disable-version-check",
            "--metrics",
            "off",
            str(target),
        ]
    if tool == "bandit":
        return ["bandit", "-r", "-q", "-f", "sarif", "-o", str(out), str(target)]
    if tool == "gitleaks":
        return [
            "gitleaks",
            "detect",
            "--no-git",
            "--no-banner",
            "--report-format",
            "json",
            "--report-path",
            str(out),
            "--source",
            str(target),
            "--exit-code",
            "0",
        ]
    raise ValueError(f"unknown tool {tool}")


def collect(
    root: Path,
    target: Path,
    with_tools: tuple[str, ...],
    imports: tuple[tuple[str, Path], ...],
    timeout: int,
    index: SourceIndex | None = None,
) -> ExternalResults:
    index = index or SourceIndex(root)
    results = ExternalResults()
    for tool in with_tools:
        _run_tool(tool, root, target, timeout, index, results)
    for fmt, report in imports:
        try:
            result = _load(fmt, report, root, index)
        except ReportError as exc:
            results.errors.append(f"import {fmt}={report}: {exc}")
            results.runs.append(ToolRun(fmt, "failed", str(exc)))
            continue
        results.add(result, ToolRun(result.tool, "imported", str(report)))
    return results


def _load(fmt: str, report: Path, root: Path, index: SourceIndex) -> ImportResult:
    if fmt == "gitleaks":
        return import_gitleaks(load_gitleaks(report), root, index)
    label = None if fmt == "sarif" else fmt
    return import_sarif(load_sarif(report), root, index, label=label)


def _run_tool(
    tool: str, root: Path, target: Path, timeout: int, index: SourceIndex, results: ExternalResults
) -> None:
    executable = shutil.which(tool)
    if executable is None:
        results.warnings.append(f"{tool}: not found on PATH; skipped")
        results.runs.append(ToolRun(tool, "missing", "not on PATH"))
        return
    with tempfile.TemporaryDirectory(prefix="hackscan-") as tmp:
        out = Path(tmp) / ("report.json" if tool == "gitleaks" else "report.sarif")
        command = _commands(tool, target, out)
        command[0] = executable
        try:
            proc = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout or None, check=False
            )
        except subprocess.TimeoutExpired:
            results.warnings.append(f"{tool}: timed out after {timeout}s; skipped")
            results.runs.append(ToolRun(tool, "timeout", f"{timeout}s"))
            return
        except OSError as exc:
            results.warnings.append(f"{tool}: could not run: {exc}; skipped")
            results.runs.append(ToolRun(tool, "failed", str(exc)))
            return
        if not out.is_file() or out.stat().st_size == 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            results.warnings.append(
                f"{tool}: produced no report (exit {proc.returncode}): {detail[0]}"
            )
            results.runs.append(ToolRun(tool, "failed", f"exit {proc.returncode}"))
            return
        try:
            result = _load(tool, out, root, index)
        except ReportError as exc:
            results.warnings.append(f"{tool}: unusable output: {exc}")
            results.runs.append(ToolRun(tool, "failed", "unusable output"))
            return
        if proc.returncode not in OK_EXIT_CODES[tool]:
            # The tool reported an error but left output: keep what it found, flag the
            # run so it is visible and `--strict-tools` fails.
            results.warnings.append(
                f"{tool}: exited with error code {proc.returncode}; results may be incomplete"
            )
            results.add(result, ToolRun(tool, "partial", f"exit {proc.returncode}"))
            return
        results.add(result, ToolRun(tool, "ok", f"exit {proc.returncode}"))
