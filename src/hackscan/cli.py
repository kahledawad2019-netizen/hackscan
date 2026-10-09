"""Command-line interface.

Exit codes: 0 = no failing findings, 1 = `--fail-on` threshold hit,
2 = usage, configuration or plugin error, an incomplete scan (a file could not be
analyzed, unless `--allow-incomplete`), or (with `--strict-tools`) an external tool error.
An incomplete scan takes precedence over findings: its results cannot be trusted to be
complete, so it must not look like a pass or an ordinary failure.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from hackscan import __version__
from hackscan.config import ConfigError, HackScanConfig, load, parse_import_format, parse_tools
from hackscan.core.models import OWN_SOURCE, Finding, Severity, Status
from hackscan.core.pipeline import ScanResult, scan
from hackscan.core.redact import redact_secretish, strip_controls
from hackscan.plugins.loader import PluginError, resolve_plugins

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
SEVERITIES = [s.value for s in Severity]
TOOL_FAILURES = {"missing", "failed", "timeout", "partial"}
REPORT_SIGNATURES = ('"name": "HackScan"', '"name": "hackscan"', "HackScan ")


@click.group()
@click.version_option(__version__, prog_name="hackscan")
def main() -> None:
    """HackScan: Python SAST orchestrator and verifier."""


@main.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--format", "fmt", type=click.Choice(["text", "json", "sarif"]), default="text")
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--severity", type=click.Choice(SEVERITIES), help="Minimum severity to report.")
@click.option("--min-confidence", type=click.IntRange(0, 100), help="Minimum confidence.")
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITIES),
    help="Exit 1 if an open finding is at least this severe.",
)
@click.option("--ignore", multiple=True, help="Glob of paths to skip (repeatable).")
@click.option("--show-suppressed", is_flag=True, default=None, help="Include suppressed findings.")
@click.option(
    "--plugins",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Directory of custom rule plugins.",
)
@click.option("--with", "with_tools", help="Run external tools: semgrep,bandit,gitleaks.")
@click.option(
    "--import",
    "imports",
    multiple=True,
    metavar="FORMAT=FILE",
    help="Import a report: sarif|semgrep|bandit|codeql|gitleaks=FILE (repeatable).",
)
@click.option("--tool-timeout", type=click.IntRange(0), help="Seconds per tool (0 = none).")
@click.option(
    "--strict-tools", is_flag=True, default=None, help="Exit 2 if an external tool fails."
)
@click.option(
    "--sarif-omit-suppressed",
    is_flag=True,
    default=False,
    help="Leave suppressed findings out of SARIF (recommended for GitHub uploads).",
)
@click.option(
    "--allow-incomplete",
    is_flag=True,
    default=None,
    help="Do not exit 2 when some files cannot be analyzed (they are still reported).",
)
@click.option("--no-taint", is_flag=True, default=False, help="Skip the taint pass.")
@click.option("--no-fix", is_flag=True, default=False, help="Do not suggest fixes.")
@click.option(
    "--llm", is_flag=True, default=None, help="Triage candidates with a local LLM (Ollama)."
)
@click.option("--model", "llm_model", help="Ollama model for --llm.")
@click.option("--ollama-host", "llm_host", help="Ollama URL (default http://localhost:11434).")
@click.option("--llm-max", type=click.IntRange(0), help="Max candidates sent to the LLM.")
@click.option("--llm-timeout", type=click.IntRange(1), help="Seconds per LLM request.")
@click.option(
    "--llm-no-suppress",
    is_flag=True,
    default=False,
    help="Let the LLM confirm and annotate, but never suppress.",
)
@click.option("--show-fixes", is_flag=True, default=False, help="Print suggested fixes as diffs.")
@click.option("--jobs", type=click.IntRange(0), help="Worker processes (0 = automatic).")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Use this config file instead of discovering .hackscan.yml.",
)
@click.option("-q", "--quiet", is_flag=True, help="Only print findings (no header/summary).")
@click.option(
    "--color",
    type=click.Choice(["auto", "always", "never"]),
    default="auto",
    help="Rich terminal output: auto = only on an interactive terminal (not CI/NO_COLOR).",
)
def scan_command(
    path: Path,
    fmt: str,
    output: Path | None,
    quiet: bool,
    config_path: Path | None,
    no_taint: bool,
    with_tools: str | None,
    imports: tuple[str, ...],
    sarif_omit_suppressed: bool,
    no_fix: bool,
    show_fixes: bool,
    llm_no_suppress: bool,
    color: str,
    **options,
) -> None:
    """Scan PATH (a directory or a Python file) for vulnerabilities."""
    if output is not None:
        _check_output(output, path)
    try:
        config = load(path, config_path).with_overrides(
            severity=Severity(options["severity"]) if options["severity"] else None,
            fail_on=Severity(options["fail_on"]) if options["fail_on"] else None,
            min_confidence=options["min_confidence"],
            ignore=tuple(options["ignore"]) or None,
            show_suppressed=options["show_suppressed"],
            plugins=options["plugins"].resolve() if options["plugins"] else None,
            tool_timeout=options["tool_timeout"],
            strict_tools=options["strict_tools"],
            allow_incomplete=options["allow_incomplete"],
            jobs=options["jobs"],
            taint=False if no_taint else None,
            fixes=False if no_fix else None,
            llm=options["llm"],
            llm_model=options["llm_model"],
            llm_host=options["llm_host"],
            llm_max=options["llm_max"],
            llm_timeout=options["llm_timeout"],
            llm_suppress=False if llm_no_suppress else None,
            with_tools=parse_tools(with_tools, click.BadParameter) if with_tools else None,
            imports=_parse_imports(imports) if imports else None,
        )
        console = _rich_console(color) if fmt == "text" and output is None and not quiet else None
        if console is not None:
            from hackscan.ui.render import banner

            banner(console)
            with console.status("[green]Scanning...", spinner="dots"):
                result = scan(path, config)
        else:
            result = scan(path, config)
        plugins = resolve_plugins(config.plugins)
    except (ConfigError, PluginError, click.BadParameter) as exc:
        click.echo(f"hackscan: error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    if fmt == "sarif":
        from hackscan.sarif.generator import export_sarif

        shown = _visible(result.findings, config, include_suppressed=True)
        log = export_sarif(_with(result, shown), plugins, omit_suppressed=sarif_omit_suppressed)
        text = json.dumps(log, indent=2)
    elif fmt == "json":
        shown = _visible(result.findings, config, config.show_suppressed)
        text = json.dumps(_json(result, shown), indent=2)
    else:
        shown = _visible(result.findings, config, config.show_suppressed)
        if console is not None:
            from hackscan.ui.render import render

            render(
                console,
                result,
                shown,
                config,
                show_fixes=show_fixes,
                diff_for=lambda f: _diff(result, f),
            )
            text = None
        else:
            text = _text(result, shown, config, quiet, show_fixes)
        if output is not None:
            text = strip_controls(text)

    if output is not None:
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text + "\n", encoding="utf-8")
        except OSError as exc:
            click.echo(f"hackscan: error: cannot write {output}: {exc}", err=True)
            sys.exit(EXIT_ERROR)
        if not quiet:
            click.echo(f"hackscan: wrote {fmt} report to {output}", err=True)
    elif text is not None:
        click.echo(text if fmt != "text" else strip_controls(text))

    if result.errors and not config.allow_incomplete:
        click.echo(
            f"hackscan: error: scan incomplete, {len(result.errors)} file(s) or report(s) "
            "could not be analyzed (see errors above; --allow-incomplete to accept)",
            err=True,
        )
        sys.exit(EXIT_ERROR)
    if config.strict_tools and any(r.status in TOOL_FAILURES for r in result.tool_runs):
        click.echo("hackscan: error: an external tool failed (--strict-tools)", err=True)
        sys.exit(EXIT_ERROR)
    if config.fail_on is not None and _failing(result.findings, config):
        sys.exit(EXIT_FINDINGS)
    sys.exit(EXIT_OK)


@main.command("rules")
@click.option("--plugins", type=click.Path(exists=True, file_okay=False, path_type=Path))
def rules_command(plugins: Path | None) -> None:
    """List the detection rules."""
    try:
        loaded = resolve_plugins(plugins)
    except PluginError as exc:
        click.echo(f"hackscan: error: {exc}", err=True)
        sys.exit(EXIT_ERROR)
    for p in loaded:
        cwe = ", ".join(p.cwe) or "-"
        click.echo(f"{p.rule_id:<16} {p.severity.value:<8} {cwe:<10} {p.description}")


# -- helpers ------------------------------------------------------------------------------


def _check_output(output: Path, target: Path) -> None:
    """A report never overwrites anything but a previous HackScan report.

    New files are fine unless they would be Python source; an existing file is only
    replaced if it already is a HackScan report (text, JSON or SARIF), so `-o
    pyproject.toml` or `-o app.py` cannot destroy project files.
    """
    resolved = output.resolve()
    refuse = resolved.suffix in {".py", ".pyw", ".pyi"} or resolved == target.resolve()
    if not refuse and resolved.exists():
        refuse = resolved.is_dir() or not _is_hackscan_report(resolved)
    if refuse:
        click.echo(
            f"hackscan: error: refusing to write the report to {output} "
            "(existing file is not a HackScan report)",
            err=True,
        )
        sys.exit(EXIT_ERROR)


def _is_hackscan_report(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return head.startswith("HackScan ") or any(sig in head for sig in REPORT_SIGNATURES[:2])


def _rich_console(color: str):
    """A Rich console when colorful interactive output is wanted, else None."""
    if color == "never":
        return None
    if color == "auto" and (
        not sys.stdout.isatty() or os.environ.get("NO_COLOR") or os.environ.get("CI")
    ):
        return None
    from rich.console import Console

    return Console(force_terminal=color == "always", highlight=False)


def _parse_imports(values: tuple[str, ...]) -> tuple[tuple[str, Path], ...]:
    out = []
    for value in values:
        fmt, sep, file = value.partition("=")
        if not sep or not file:
            raise click.BadParameter(f"--import expects FORMAT=FILE, got {value!r}")
        report = Path(file)
        if not report.is_file():
            raise click.BadParameter(f"--import report not found: {file}")
        out.append((parse_import_format(fmt, click.BadParameter), report.resolve()))
    return tuple(out)


def _visible(
    findings: list[Finding], config: HackScanConfig, include_suppressed: bool
) -> list[Finding]:
    return [
        f
        for f in findings
        if f.severity.rank >= config.severity.rank
        and f.confidence >= config.min_confidence
        and (include_suppressed or f.status is not Status.SUPPRESSED)
    ]


def _failing(findings: list[Finding], config: HackScanConfig) -> list[Finding]:
    """Open (candidate/confirmed) findings at or above --fail-on; suppressed never count."""
    assert config.fail_on is not None
    return [
        f
        for f in findings
        if f.status is not Status.SUPPRESSED
        and f.severity.rank >= config.fail_on.rank
        and f.confidence >= config.min_confidence
    ]


def _with(result: ScanResult, findings: list[Finding]) -> ScanResult:
    return ScanResult(
        root=result.root,
        findings=findings,
        files_scanned=result.files_scanned,
        duration_seconds=result.duration_seconds,
        errors=result.errors,
        warnings=result.warnings,
        tool_runs=result.tool_runs,
    )


def _diff(result: ScanResult, finding: Finding) -> str:
    import ast
    import difflib

    from hackscan.analyzers.remediate import apply_edits
    from hackscan.core.redact import mask_secret_literals

    try:
        path = result.root / finding.location.path
        source = path.read_text(encoding="utf-8")
        fixed = apply_edits(source, finding.fix.edits)
        # Each side is masked from its own syntax tree: the replacement may carry a
        # secret too (e.g. a copied `password="..."` keyword).
        before = mask_secret_literals(source, ast.parse(source))
        after = mask_secret_literals(fixed, ast.parse(fixed))
    except (OSError, UnicodeDecodeError, ValueError, SyntaxError):
        return ""
    name = finding.location.path
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )
    # Diff context shows raw source: redact anything secret-looking before printing.
    return "\n".join(redact_secretish(line, result.secrets) for line in diff.splitlines())


def _json(result: ScanResult, findings: list[Finding]) -> dict:
    return {
        "tool": {"name": "hackscan", "version": __version__},
        "root": result.root.as_posix(),
        "stats": {
            "files_scanned": result.files_scanned,
            "duration_seconds": round(result.duration_seconds, 3),
            "findings": len(findings),
            "by_status": {s.value: sum(f.status is s for f in findings) for s in Status},
        },
        "findings": [f.to_dict() for f in findings],
        "errors": result.errors,
        "warnings": result.warnings,
        "tool_runs": [vars(r) for r in result.tool_runs],
    }


def _text(
    result: ScanResult,
    findings: list[Finding],
    config: HackScanConfig,
    quiet: bool,
    show_fixes: bool = False,
) -> str:
    lines: list[str] = []
    if not quiet:
        lines.append(
            f"HackScan {__version__} - scanned {result.files_scanned} files "
            f"in {result.duration_seconds:.2f}s"
        )
        lines.append("")
    ordered = sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.status is not Status.CONFIRMED, f.sort_key()),
    )
    for f in ordered:
        loc = f"{f.location.path}:{f.location.start_line}:{f.location.start_column}"
        status = f.status.value
        if f.status is Status.SUPPRESSED:
            status = f"suppressed ({f.suppression})"
        lines.append(
            f"{f.severity.value.upper():<8} {status:<10} {loc}  {f.rule_id}  [{f.confidence}%]"
        )
        lines.append(f"    {f.message}")
        if f.snippet:
            lines.append(f"    | {f.snippet.splitlines()[0].strip()}")
        lines.extend(
            f"    > {e.message}"
            for e in f.evidence
            if e.kind
            in {"taint_step", "taint_verdict", "llm_rationale", "llm_evidence", "llm_note"}
        )
        if f.sources != (OWN_SOURCE,):
            lines.append(f"    sources: {', '.join(f.sources)}")
        if f.fix is not None:
            lines.append(f"    fix: {f.fix.description}")
            if show_fixes:
                lines.extend(f"      {line}" for line in _diff(result, f).splitlines())
    if quiet:
        return "\n".join(lines)
    counts = {s: sum(f.status is s for f in findings) for s in Status}
    hidden = sum(f.status is Status.SUPPRESSED for f in result.findings) - counts[Status.SUPPRESSED]
    if not findings:
        lines.append("No findings.")
    lines.append("")
    summary = (
        f"Summary: {counts[Status.CONFIRMED]} confirmed, {counts[Status.CANDIDATE]} candidates"
    )
    if counts[Status.SUPPRESSED]:
        summary += f", {counts[Status.SUPPRESSED]} suppressed shown"
    if hidden:
        summary += f", {hidden} suppressed hidden (--show-suppressed)"
    lines.append(summary)
    if result.errors:
        lines.append(f"INCOMPLETE: {len(result.errors)} file(s) could not be analyzed")
    lines.extend(f"error: {e}" for e in result.errors)
    lines.extend(f"warning: {w}" for w in result.warnings)
    if config.fail_on is not None:
        failing = len(_failing(result.findings, config))
        lines.append(f"fail-on {config.fail_on.value}: {failing} open finding(s) at or above")
    return "\n".join(lines)
