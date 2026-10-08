"""Rich rendering for interactive terminals.

Plain text (`cli._text`) stays the format for pipes, CI logs and tests; this module is
used only when stdout is a terminal (or `--color always`). Both show the same facts.
"""

from __future__ import annotations

from collections import Counter

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from hackscan import __version__
from hackscan.core.models import OWN_SOURCE, Finding, Severity, Status
from hackscan.core.redact import strip_controls as _safe

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}
STATUS_STYLE = {
    Status.CONFIRMED: "bold red",
    Status.CANDIDATE: "yellow",
    Status.SUPPRESSED: "dim",
}
ACCENT = "green"
EVIDENCE_KINDS = {"taint_step", "taint_verdict", "llm_rationale", "llm_evidence", "llm_note"}

BANNER = r"""
 _   _            _    ____
| | | | __ _  ___| | _/ ___|  ___ __ _ _ __
| |_| |/ _` |/ __| |/ \___ \ / __/ _` | '_ \
|  _  | (_| | (__|   < ___) | (_| (_| | | | |
|_| |_|\__,_|\___|_|\_\____/ \___\__,_|_| |_|
"""


def banner(console: Console) -> None:
    console.print(Text(BANNER.strip("\n"), style=f"bold {ACCENT}"))
    console.print(Text(f"  v{__version__}  verify what you report", style=f"dim {ACCENT}"))
    console.print()


def render(
    console: Console,
    result,
    findings: list[Finding],
    config,
    *,
    show_fixes: bool = False,
    diff_for=None,
) -> None:
    ordered = sorted(
        findings,
        key=lambda f: (-f.severity.rank, f.status is not Status.CONFIRMED, f.sort_key()),
    )
    for f in ordered:
        console.print(_finding_panel(f, show_fixes, diff_for))
    console.print(_summary(result, findings, config))
    for e in result.errors:
        console.print(Text(_safe(f"error: {e}"), style="bold red"))
    for w in result.warnings:
        console.print(Text(_safe(f"warning: {w}"), style="yellow"))


def _finding_panel(f: Finding, show_fixes: bool, diff_for) -> Panel:
    title = Text.assemble(
        (f" {f.severity.value.upper()} ", SEVERITY_STYLE[f.severity]),
        " ",
        (f.status.value, STATUS_STYLE[f.status]),
        "  ",
        (f.rule_id, "bold"),
        ("  " + f"{f.confidence}%", "dim"),
    )
    location = _safe(f"{f.location.path}:{f.location.start_line}:{f.location.start_column}")
    body: list = [Text(location, style=f"bold {ACCENT}"), Text(_safe(f.message))]
    if f.status is Status.SUPPRESSED:
        body.append(Text(_safe(f"suppressed: {f.suppression}"), style="dim"))
    if f.snippet:
        first = _safe(f.snippet.splitlines()[0])
        body.append(Syntax(first.strip(), "python", theme="ansi_dark", background_color="default"))
    for e in f.evidence:
        if e.kind in EVIDENCE_KINDS:
            marker = "LLM" if e.producer == "llm" else ">"
            body.append(Text(_safe(f"{marker} {e.message}"), style="italic"))
    if f.sources != (OWN_SOURCE,):
        body.append(Text(_safe(f"sources: {', '.join(f.sources)}"), style="dim"))
    if f.fix is not None:
        body.append(Text(_safe(f"fix: {f.fix.description}"), style=ACCENT))
        if show_fixes and diff_for is not None:
            diff = diff_for(f)
            if diff:
                body.append(
                    Syntax(_safe(diff), "diff", theme="ansi_dark", background_color="default")
                )
    border = (
        "red"
        if f.status is Status.CONFIRMED
        else ("grey50" if f.status is Status.SUPPRESSED else "yellow")
    )
    return Panel(
        Group(*body), title=title, title_align="left", border_style=border, box=box.ROUNDED
    )


def _summary(result, findings: list[Finding], config) -> Panel:
    table = Table(box=box.SIMPLE_HEAVY, show_edge=False, header_style=f"bold {ACCENT}")
    table.add_column("severity")
    for status in Status:
        table.add_column(status.value, justify="right")
    counts = Counter((f.severity, f.status) for f in findings)
    for severity in sorted(Severity, key=lambda s: -s.rank):
        row = [counts[(severity, s)] for s in Status]
        if any(row):
            table.add_row(
                Text(severity.value, style=SEVERITY_STYLE[severity]),
                *(str(n) if n else "-" for n in row),
            )
    hidden = sum(f.status is Status.SUPPRESSED for f in result.findings) - sum(
        f.status is Status.SUPPRESSED for f in findings
    )
    lines: list = [
        Text(
            f"{result.files_scanned} files in {result.duration_seconds:.2f}s"
            + (f", {result.llm_reviewed} reviewed by LLM" if result.llm_reviewed else ""),
            style="dim",
        )
    ]
    lines.append(table if findings else Text("No findings.", style=f"bold {ACCENT}"))
    if hidden:
        lines.append(Text(f"{hidden} suppressed hidden (--show-suppressed)", style="dim"))
    if result.errors:
        lines.append(
            Text(
                f"INCOMPLETE: {len(result.errors)} file(s) could not be analyzed", style="bold red"
            )
        )
    if config.fail_on is not None:
        from hackscan.cli import _failing

        failing = len(_failing(result.findings, config))
        style = "bold red" if failing else f"bold {ACCENT}"
        lines.append(
            Text(
                f"fail-on {config.fail_on.value}: {failing} open finding(s) at or above",
                style=style,
            )
        )
    return Panel(Group(*lines), title="Summary", title_align="left", border_style=ACCENT)
