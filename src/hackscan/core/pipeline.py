"""Scan pipeline: discover -> analyze (passes 1-2, parallel) -> import -> merge -> ids.

Pipeline order per PROJECT.md: collect (own engine + importers) -> `merge_findings` ->
`assign_ids`. Output is deterministic regardless of worker scheduling.
"""

from __future__ import annotations

import fnmatch
import os
import time
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from hackscan.analyzers.ast_pass import FileResult, analyze_file, analyze_source
from hackscan.analyzers.llm_pass import LLMConfig, default_cache_dir, triage
from hackscan.analyzers.remediate import generate_fixes
from hackscan.config import DEFAULT_IGNORES, HackScanConfig
from hackscan.core.dedupe import merge_findings
from hackscan.core.fingerprint import assign_ids
from hackscan.core.models import Finding
from hackscan.core.redact import redact_findings, redact_messages
from hackscan.importers.common import SourceIndex
from hackscan.importers.runner import ToolRun, collect
from hackscan.plugins.base import RulePlugin
from hackscan.plugins.loader import resolve_plugins

PARALLEL_THRESHOLD = 16  # below this many files, process start-up costs more than it saves


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding]
    files_scanned: int
    duration_seconds: float
    errors: list[str] = field(default_factory=list)  # files we could not analyze
    warnings: list[str] = field(default_factory=list)  # external tool problems
    tool_runs: list[ToolRun] = field(default_factory=list)
    llm_reviewed: int = 0
    # Values to redact from any raw text shown later (e.g. fix diffs). Never exported.
    secrets: frozenset[str] = field(default=frozenset(), repr=False)


def scan(target: Path, config: HackScanConfig) -> ScanResult:
    started = time.perf_counter()
    target = target.resolve()
    root = target if target.is_dir() else target.parent
    plugins = resolve_plugins(config.plugins)
    files = list(discover_files(target, root, config.ignore))

    results = _analyze(files, root, plugins, config)
    findings: list[Finding] = []
    errors: list[str] = []
    known_secrets: set[str] = set()
    for result in results:
        findings.extend(result.findings)
        errors.extend(result.errors)
        known_secrets.update(result.secrets)

    index = SourceIndex(root)
    external = collect(
        root,
        target,
        config.with_tools,
        config.imports,
        config.tool_timeout,
        index,
    )
    # Imported findings obey the same ignores as discovery (defaults included).
    findings.extend(
        f for f in external.findings if not is_ignored_path(f.location.path, config.ignore)
    )

    known_secrets.update(index.secret_values)
    known_secrets.update(external.secrets)
    final = assign_ids(redact_findings(merge_findings(findings), known_secrets))
    if config.fixes:
        final = generate_fixes(final, index)
    warnings = list(external.warnings)
    llm_reviewed = 0
    if config.llm:
        report = triage(
            final,
            index,
            LLMConfig(
                host=config.llm_host,
                model=config.llm_model,
                max_findings=config.llm_max,
                timeout=config.llm_timeout,
                allow_suppress=config.llm_suppress,
                cache_dir=default_cache_dir(),
            ),
            secrets=known_secrets,
            rescan=lambda source, path: (
                analyze_source(source, path, plugins, taint=config.taint).findings
            ),
        )
        # Model text is untrusted too: redact again before anything is printed.
        final = redact_findings(report.findings, known_secrets)
        warnings.extend(report.warnings)
        llm_reviewed = report.reviewed
    return ScanResult(
        root=root,
        findings=final,
        files_scanned=len(files),
        duration_seconds=time.perf_counter() - started,
        errors=redact_messages([*sorted(errors), *external.errors], known_secrets),
        warnings=redact_messages(warnings, known_secrets),
        llm_reviewed=llm_reviewed,
        secrets=frozenset(known_secrets),
        tool_runs=external.runs,
    )


# -- discovery ----------------------------------------------------------------------------


def discover_files(target: Path, root: Path, ignore: tuple[str, ...]) -> Iterator[Path]:
    """Python files under `target`, skipping default and configured ignores (sorted)."""
    if target.is_file():
        if target.suffix in (".py", ".pyw") and not _is_ignored(target.name, ignore):
            yield target
        return
    for dirpath, dirnames, filenames in os.walk(target):
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()
        dirnames[:] = sorted(
            d
            for d in dirnames
            if not _is_ignored(f"{rel_dir}/{d}" if rel_dir != "." else d, ignore, is_dir=True)
        )
        for name in sorted(filenames):
            if not name.endswith((".py", ".pyw")):
                continue
            rel = f"{rel_dir}/{name}" if rel_dir != "." else name
            if not _is_ignored(rel, ignore):
                yield current / name


def is_ignored_path(rel_path: str, patterns: tuple[str, ...]) -> bool:
    """Whether a file path is excluded: any directory component matching a default ignore
    (`.venv`, `node_modules`, ...) or a configured pattern."""
    parts = rel_path.split("/")
    if any(fnmatch.fnmatch(part, p) for part in parts[:-1] for p in DEFAULT_IGNORES):
        return True
    return _is_ignored(rel_path, patterns)


def _is_ignored(rel_path: str, patterns: tuple[str, ...], is_dir: bool = False) -> bool:
    """Default ignores match any path component; configured globs match the relative path
    (`tests/*`, `**/migrations/**`) or any single component (`legacy`)."""
    parts = rel_path.split("/")
    if is_dir and any(fnmatch.fnmatch(parts[-1], p) for p in DEFAULT_IGNORES):
        return True
    for pattern in patterns:
        pattern = pattern.strip().rstrip("/")
        if not pattern:
            continue
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path, pattern + "/*"):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(rel_path, pattern[3:]):
            return True
        if "/" not in pattern and any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


# -- analysis -----------------------------------------------------------------------------

_WORKER_STATE: dict = {}


def _worker_init(plugins_dir: str | None, taint: bool) -> None:
    _WORKER_STATE["plugins"] = resolve_plugins(Path(plugins_dir) if plugins_dir else None)
    _WORKER_STATE["taint"] = taint


def _worker_analyze(args: tuple[str, str]) -> FileResult:
    path, root = args
    return analyze_file(
        Path(path), Path(root), _WORKER_STATE["plugins"], taint=_WORKER_STATE["taint"]
    )


def _analyze(
    files: list[Path], root: Path, plugins: list[RulePlugin], config: HackScanConfig
) -> list[FileResult]:
    jobs = config.jobs or min(8, os.cpu_count() or 1)
    if jobs <= 1 or len(files) < PARALLEL_THRESHOLD:
        return [analyze_file(f, root, plugins, taint=config.taint) for f in files]
    plugins_dir = str(config.plugins) if config.plugins else None
    with ProcessPoolExecutor(
        max_workers=jobs, initializer=_worker_init, initargs=(plugins_dir, config.taint)
    ) as pool:
        chunk = max(1, len(files) // (jobs * 4))
        return list(
            pool.map(_worker_analyze, [(str(f), str(root)) for f in files], chunksize=chunk)
        )
