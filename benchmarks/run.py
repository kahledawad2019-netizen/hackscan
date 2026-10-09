"""Benchmark HackScan against Bandit, Semgrep CE and CodeQL on a labeled suite.

Ground truth lives in `benchmarks/suite/`: a sink statement carries `# vuln: <class>`
(untrusted input reaches it) or `# safe: <class>` (a trap: it looks like a sink but no
untrusted input reaches it). Classes are HackScan's canonical ones: sqli, cmdi, codei,
weak_crypto. Every tool's report is normalized through HackScan's SARIF importer to
(file, line, class); reports in other classes are ignored.

Tools report a flow at different points (sink, query construction, source), so scoring
is per function: each function holds at most one labeled sink, and a report counts for
the function whose body contains its line.
- TP: a function with a `vuln` label and at least one report of that class;
- FN: a function with a `vuln` label and none;
- FP: a function (or module-level code) with reports of a class but no `vuln` label of
  that class; `trap_hits` counts the FPs in functions labeled `safe`.

Usage: `uv run python benchmarks/run.py [--tools hackscan,bandit,semgrep,codeql]`.
External tools run in isolated environments via `uvx` (pinned versions); the Semgrep
ruleset is pinned by digest; CodeQL needs the `codeql` CLI on PATH or
`CODEQL=<path to codeql executable>`. A tool that cannot run, or whose report cannot be
imported completely, is reported as skipped, never as zero findings.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from hackscan import __version__
from hackscan.config import HackScanConfig
from hackscan.core.models import Status
from hackscan.core.pipeline import scan
from hackscan.importers.common import SourceIndex
from hackscan.importers.sarif import import_sarif

HERE = Path(__file__).resolve().parent
SUITE = HERE / "suite"
CACHE = HERE / ".cache"
CLASSES = ("sqli", "cmdi", "codei", "weak_crypto")
LABEL_RE = re.compile(r"#\s*(?P<kind>vuln|safe):\s*(?P<cls>[a-z_]+)")
BANDIT = "bandit[sarif]==1.9.4"
SEMGREP = "semgrep==1.180.0"
# The registry ruleset changes over time and its license does not allow vendoring it, so
# it is downloaded once into the (git-ignored) cache and pinned by digest.
SEMGREP_RULES_URL = "https://semgrep.dev/c/p/python"
SEMGREP_RULES_SHA256 = "31c1dfa46e8ddd97f9ac98c607ddd77b20a2c3356d7ec987359961d47ec27035"
CODEQL_SUITE = "codeql/python-queries:codeql-suites/python-security-extended.qls"
TIMEOUT = 1800


@dataclass(frozen=True, order=True)
class Label:
    path: str
    line: int
    function: str  # qualified name of the enclosing function
    cls: str
    vulnerable: bool


@dataclass(frozen=True, order=True)
class Report:
    path: str
    line: int
    cls: str
    rule: str = field(default="", compare=False)  # for review listings only


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    trap_hits: int = 0  # FPs on a labeled `safe` trap (subset of fp)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def f1(self) -> float | None:
        total = 2 * self.tp + self.fp + self.fn
        return 2 * self.tp / total if total else None


@dataclass
class ToolResult:
    name: str
    version: str
    reports: list[Report] = field(default_factory=list)
    skipped: str | None = None


# -- ground truth -------------------------------------------------------------------------


def functions(source: str) -> list[tuple[int, int, str]]:
    """(first line, last line, qualified name) of every function, innermost last."""
    found: list[tuple[int, int, str]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = f"{prefix}{child.name}"
                if not isinstance(child, ast.ClassDef):
                    first = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                    found.append((first, child.end_lineno or child.lineno, name))
                visit(child, f"{name}.")
            else:
                visit(child, prefix)

    visit(ast.parse(source), "")
    return found


def enclosing(spans: list[tuple[int, int, str]], line: int) -> str:
    inside = [s for s in spans if s[0] <= line <= s[1]]
    return max(inside, key=lambda s: s[0])[2] if inside else "<module>"


def load_labels(suite: Path = SUITE) -> list[Label]:
    labels: list[Label] = []
    for file in sorted(suite.rglob("*.py")):
        rel = file.relative_to(suite).as_posix()
        source = file.read_text(encoding="utf-8")
        statements = {n.lineno for n in ast.walk(ast.parse(source)) if isinstance(n, ast.stmt)}
        spans = functions(source)
        seen: set[str] = set()
        for number, text in enumerate(source.splitlines(), 1):
            match = LABEL_RE.search(text)
            if match is None:
                continue
            cls = match.group("cls")
            if cls not in CLASSES:
                raise ValueError(f"{rel}:{number}: unknown class {cls!r}")
            if number not in statements:
                raise ValueError(f"{rel}:{number}: label is not on a statement's first line")
            function = enclosing(spans, number)
            if function == "<module>" or function in seen:
                raise ValueError(f"{rel}:{number}: one labeled sink per function required")
            seen.add(function)
            labels.append(Label(rel, number, function, cls, match.group("kind") == "vuln"))
    return labels


# -- scoring ------------------------------------------------------------------------------


def score(
    labels: Iterable[Label], reports: Iterable[Report], suite: Path = SUITE
) -> dict[str, Score]:
    """Per-class scores plus "all" (see the module docstring)."""
    labels = list(labels)
    scores = {cls: Score() for cls in (*CLASSES, "all")}
    spans: dict[str, list[tuple[int, int, str]]] = {}
    reported: set[tuple[str, str, str]] = set()  # (path, function, class)
    for r in reports:
        if r.cls not in CLASSES:
            continue
        if r.path not in spans:
            file = suite / r.path
            spans[r.path] = functions(file.read_text(encoding="utf-8")) if file.exists() else []
        reported.add((r.path, enclosing(spans[r.path], r.line), r.cls))
    by_key = {(lb.path, lb.function, lb.cls): lb for lb in labels}
    for label in labels:
        if label.vulnerable:
            hit = (label.path, label.function, label.cls) in reported
            for key in (label.cls, "all"):
                if hit:
                    scores[key].tp += 1
                else:
                    scores[key].fn += 1
    for path, function, cls in sorted(reported):
        label = by_key.get((path, function, cls))
        if label is not None and label.vulnerable:
            continue
        for key in (cls, "all"):
            scores[key].fp += 1
            if label is not None:
                scores[key].trap_hits += 1
    return scores


# -- tools --------------------------------------------------------------------------------


def run_hackscan(suite: Path, confirmed_only: bool = False) -> ToolResult:
    result = scan(suite, HackScanConfig())
    wanted = {Status.CONFIRMED} if confirmed_only else {Status.CONFIRMED, Status.CANDIDATE}
    name = "HackScan (confirmed only)" if confirmed_only else "HackScan"
    reports = [
        Report(f.location.path, f.location.start_line, f.vuln_class, f.rule_id)
        for f in result.findings
        if f.status in wanted
    ]
    return ToolResult(name, __version__, reports)


def sarif_reports(sarif: Path, root: Path, label: str) -> tuple[list[Report], str | None]:
    """Reports from a SARIF file, or an explanation why it cannot be scored completely
    (unreadable, not a SARIF log, or results the importer dropped)."""
    try:
        data = json.loads(sarif.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [], f"unreadable SARIF: {exc}"
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list) or not runs:
        return [], "not a SARIF log (no runs)"
    expected = 0
    for run in runs:
        results = run.get("results") if isinstance(run, dict) else None
        if not isinstance(results, list):
            return [], "a SARIF run has no result list"
        expected += len(results)
    try:
        imported = import_sarif(data, root, SourceIndex(root), label=label)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        return [], f"SARIF could not be imported: {exc}"
    if imported.warnings or len(imported.findings) != expected:
        lost = expected - len(imported.findings)
        detail = imported.warnings[0] if imported.warnings else "no importer warning"
        return [], f"{lost} of {expected} results not imported ({detail})"
    reports = [
        Report(f.location.path, f.location.start_line, f.vuln_class, f.rule_id)
        for f in imported.findings
    ]
    return reports, None


def _env() -> dict[str, str]:
    # PYTHONUTF8: Semgrep writes non-ASCII (emoji) output that fails on cp1252 consoles.
    # PATH: CodeQL's Python extractor runs `python`; use this interpreter (and not the
    # Windows `py` launcher, which a uv-managed Python does not have).
    path = os.pathsep.join([str(Path(sys.executable).parent), os.environ.get("PATH", "")])
    return {
        **os.environ,
        "PYTHONUTF8": "1",
        "PATH": path,
        "CODEQL_EXTRACTOR_PYTHON_OPTION_PYTHON_EXECUTABLE_NAME": "python",
    }


def _run(command: list[str], ok: set[int], cwd: Path | None = None) -> tuple[str, str | None]:
    """Run a tool; return (stdout, error description or None on success)."""
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            env=_env(),
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"{Path(command[0]).name}: {exc}"
    if proc.returncode not in ok:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        return proc.stdout, f"exit {proc.returncode}: {' | '.join(tail)}"
    return proc.stdout, None


def _scored(name: str, version: str, out: Path, root: Path, label: str) -> ToolResult:
    if not out.exists():
        return ToolResult(name, version, skipped="no report")
    reports, problem = sarif_reports(out, root, label)
    return ToolResult(name, version, reports, skipped=problem)


def run_bandit(suite: Path) -> ToolResult:
    if shutil.which("uvx") is None:
        return ToolResult("Bandit", BANDIT, skipped="uvx not found")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bandit.sarif"
        cmd = ["uvx", "--from", BANDIT, "bandit", "-r", "-q", "-f", "sarif", "-o", str(out)]
        _, error = _run([*cmd, str(suite)], {0, 1})
        if error:
            return ToolResult("Bandit", BANDIT, skipped=error)
        return _scored("Bandit", BANDIT, out, suite, "bandit")


def semgrep_rules() -> tuple[Path | None, str]:
    """The pinned ruleset (downloaded once), or None and the reason it is unusable."""
    rules = CACHE / "semgrep-p-python.yml"
    if not rules.exists():
        try:
            with urllib.request.urlopen(SEMGREP_RULES_URL, timeout=120) as response:  # noqa: S310
                data = response.read(20 * 1024 * 1024)
        except OSError as exc:
            return None, f"cannot download {SEMGREP_RULES_URL}: {exc}"
        CACHE.mkdir(exist_ok=True)
        rules.write_bytes(data)
    digest = hashlib.sha256(rules.read_bytes()).hexdigest()
    if digest != SEMGREP_RULES_SHA256:
        return None, (
            f"p/python ruleset changed (sha256 {digest[:12]}, pinned "
            f"{SEMGREP_RULES_SHA256[:12]}); review it, update SEMGREP_RULES_SHA256, re-run"
        )
    return rules, digest


def run_semgrep(suite: Path) -> ToolResult:
    version = f"{SEMGREP} (p/python sha256:{SEMGREP_RULES_SHA256[:12]})"
    if shutil.which("uvx") is None:
        return ToolResult("Semgrep CE", version, skipped="uvx not found")
    rules, detail = semgrep_rules()
    if rules is None:
        return ToolResult("Semgrep CE", version, skipped=detail)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "semgrep.sarif"
        cmd = [
            "uvx",
            SEMGREP,
            "scan",
            "--config",
            rules.name,  # relative to cwd, so rule ids carry no directory prefix
            "--sarif",
            "--output",
            str(out),
            "--metrics",
            "off",
            "--disable-version-check",
            "--no-git-ignore",  # scan targets inside ignored dirs (benchmarks/.cache)
            "--quiet",
            str(suite),
        ]
        _, error = _run(cmd, {0, 1}, cwd=rules.parent)
        if error:
            return ToolResult("Semgrep CE", version, skipped=error)
        return _scored("Semgrep CE", version, out, suite, "semgrep")


def _codeql_packs(sarif: Path) -> str:
    """Query pack versions recorded in the SARIF log (`codeql/python-queries@1.2.3`)."""
    try:
        data = json.loads(sarif.read_text(encoding="utf-8"))
        extensions = data["runs"][0]["tool"].get("extensions", [])
    except (OSError, ValueError, KeyError, IndexError, TypeError, AttributeError):
        return ""
    packs = []
    for e in extensions if isinstance(extensions, list) else []:
        version = e.get("semanticVersion") or e.get("version") if isinstance(e, dict) else None
        if version and str(e.get("name", "")).endswith("python-queries"):
            packs.append(f"{e['name']}@{str(version).split('+')[0]}")
    return ", ".join(sorted(packs))


def run_codeql(suite: Path) -> ToolResult:
    codeql = os.environ.get("CODEQL") or shutil.which("codeql")
    if not codeql:
        return ToolResult("CodeQL", "-", skipped="codeql CLI not found (set CODEQL)")
    stdout, error = _run([codeql, "version", "--format=terse"], {0})
    if error:
        return ToolResult("CodeQL", "-", skipped=error)
    version = f"CodeQL {stdout.strip()}"
    with tempfile.TemporaryDirectory() as tmp:
        db, out = Path(tmp) / "db", Path(tmp) / "codeql.sarif"
        create = [codeql, "database", "create", str(db), "--language=python"]
        _, error = _run([*create, f"--source-root={suite}", "--overwrite"], {0})
        if error is None:
            analyze = [codeql, "database", "analyze", str(db), CODEQL_SUITE]
            _, error = _run([*analyze, "--format=sarif-latest", f"--output={out}"], {0})
        if error:
            return ToolResult("CodeQL", version, skipped=error)
        packs = _codeql_packs(out)
        version += f" ({packs or 'python-queries'}, security-extended)"
        return _scored("CodeQL", version, out, suite, "codeql")


TOOLS: dict[str, Callable[[Path], list[ToolResult]]] = {
    "hackscan": lambda s: [run_hackscan(s), run_hackscan(s, confirmed_only=True)],
    "bandit": lambda s: [run_bandit(s)],
    "semgrep": lambda s: [run_semgrep(s)],
    "codeql": lambda s: [run_codeql(s)],
}


# -- report -------------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


def to_json(labels: list[Label], results: list[ToolResult]) -> dict:
    vulnerable = sum(lb.vulnerable for lb in labels)
    out: dict = {
        "generated": date.today().isoformat(),
        "vulnerable": vulnerable,
        "safe": len(labels) - vulnerable,
        "files": len({lb.path for lb in labels}),
        "tools": {},
    }
    for result in results:
        entry: dict = {"version": result.version, "skipped": result.skipped}
        if not result.skipped:
            entry["scores"] = {
                cls: {"tp": s.tp, "fp": s.fp, "fn": s.fn, "trap_hits": s.trap_hits}
                for cls, s in score(labels, result.reports).items()
            }
        out["tools"][result.name] = entry
    return out


def overall_rows(data: dict) -> list[str]:
    """The overall table's rows, as RESULTS.md and README.md show them."""
    rows = []
    for name, entry in data["tools"].items():
        if entry["skipped"]:
            rows.append(f"| {name} | {entry['version']} | skipped: {entry['skipped']} |||||| ")
            continue
        s = Score(**entry["scores"]["all"])
        rows.append(
            f"| {name} | {entry['version']} | {s.tp} | {s.fp} | {s.fn} | "
            f"{_pct(s.precision)} | {_pct(s.recall)} | {_pct(s.f1)} |"
        )
    return rows


def render(data: dict) -> str:
    lines = [
        "# Benchmark results",
        "",
        f"Generated {data['generated']} by `benchmarks/run.py` on `benchmarks/suite/`: "
        f"{data['vulnerable']} vulnerable sinks and {data['safe']} safe traps across "
        f"{data['files']} files ({', '.join(CLASSES)}).",
        "",
        "| Tool | Version | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
        *overall_rows(data),
        "",
        "Per class (TP / FP / FN):",
        "",
        "| Tool | " + " | ".join(CLASSES) + " |",
        "|---|" + "---:|" * len(CLASSES),
    ]
    for name, entry in data["tools"].items():
        if entry["skipped"]:
            continue
        cells = ["{tp} / {fp} / {fn}".format(**entry["scores"][c]) for c in CLASSES]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tools", default=",".join(TOOLS))
    parser.add_argument("--out", type=Path, default=HERE / "RESULTS.md")
    args = parser.parse_args(argv)
    labels = load_labels()
    results: list[ToolResult] = []
    for name in args.tools.split(","):
        if name not in TOOLS:
            parser.error(f"unknown tool {name!r}")
        results.extend(TOOLS[name](SUITE))
    data = to_json(labels, results)
    args.out.write_text(render(data), encoding="utf-8")
    args.out.with_suffix(".json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(render(data))
    return 1 if any(r.skipped for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
