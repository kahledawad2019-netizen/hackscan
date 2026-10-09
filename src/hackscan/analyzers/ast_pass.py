"""Pass 1: run AST rule plugins over a file and emit candidate findings."""

from __future__ import annotations

import ast
import io
import tokenize
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from hackscan.analyzers.interproc import FileFacts
from hackscan.analyzers.suppressions import apply_inline_suppressions
from hackscan.analyzers.taint_pass import analyze_taint
from hackscan.core.models import OWN_SOURCE, Evidence, Finding, Region
from hackscan.core.redact import file_secret_literal_values, secret_literal_values
from hackscan.core.taxonomy import classify
from hackscan.plugins.base import FileContext, Match, RulePlugin

PRODUCER = "ast"


@dataclass
class FileResult:
    path: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    secrets: set[str] = field(default_factory=set)
    file_secrets: set[str] = field(default_factory=set)
    facts: FileFacts | None = None  # inter-procedural facts (pass 2b)


def analyze_source(
    source: str,
    rel_path: str,
    plugins: Sequence[RulePlugin],
    *,
    taint: bool = True,
    link: bool = False,
) -> FileResult:
    """Parse `source`, run every plugin (pass 1), then taint (pass 2) and inline
    suppressions. Parse and plugin errors are reported, not raised."""
    result = FileResult(path=rel_path)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)  # e.g. invalid escapes in scanned code
            tree = ast.parse(source, filename=rel_path, type_comments=False)
    except (SyntaxError, ValueError) as exc:
        result.errors.append(f"{rel_path}: cannot parse: {exc}")
        return result

    result.secrets = secret_literal_values(tree, source)
    result.file_secrets = file_secret_literal_values(tree, source)
    ctx = FileContext(path=rel_path, source=source, tree=tree)
    by_type: dict[type[ast.AST], list[RulePlugin]] = {}
    for plugin in plugins:
        for node_type in plugin.node_types:
            by_type.setdefault(node_type, []).append(plugin)

    qualnames = _qualnames(tree)
    candidates: list[tuple[Finding, Match]] = []
    for node in ast.walk(tree):
        for plugin in by_type.get(type(node), ()):
            try:
                matches = list(plugin.check(node, ctx))
            except Exception as exc:  # a broken rule must not abort the scan
                line = getattr(node, "lineno", "?")
                result.errors.append(f"{rel_path}:{line}: rule {plugin.rule_id} failed: {exc}")
                continue
            for match in matches:
                try:
                    candidates.append((_to_finding(match, plugin, ctx, qualnames), match))
                except Exception as exc:  # malformed match from a (user) plugin
                    line = getattr(node, "lineno", "?")
                    result.errors.append(
                        f"{rel_path}:{line}: rule {plugin.rule_id} returned a bad match: {exc}"
                    )
    findings = [f for f, _ in candidates]
    if taint:
        try:
            findings, result.facts = analyze_taint(ctx, candidates, link=link)
        except RecursionError:  # pathological nesting: keep pass-1 candidates
            result.errors.append(f"{rel_path}: taint analysis skipped (nesting too deep)")
    findings = apply_inline_suppressions(findings, ctx)
    result.findings = sorted(findings, key=Finding.sort_key)
    return result


def analyze_file(
    path: Path,
    root: Path,
    plugins: Sequence[RulePlugin],
    *,
    taint: bool = True,
    link: bool = False,
) -> FileResult:
    rel_path = path.relative_to(root).as_posix()
    try:
        data = path.read_bytes()
        # Honors PEP 263 coding declarations and BOMs, defaulting to UTF-8.
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        source = data.decode(encoding)
    except (OSError, SyntaxError, UnicodeDecodeError, LookupError) as exc:
        return FileResult(path=rel_path, errors=[f"{rel_path}: cannot read: {exc}"])
    return analyze_source(source, rel_path, plugins, taint=taint, link=link)


def _to_finding(
    match: Match, plugin: RulePlugin, ctx: FileContext, qualnames: dict[int, str]
) -> Finding:
    node = match.node
    if not isinstance(node, ast.AST) or not hasattr(node, "lineno"):
        raise TypeError(f"match node must be a located AST node, got {type(node).__name__}")
    start_line = node.lineno
    end_line = node.end_lineno or start_line
    region = Region(
        path=ctx.path,
        start_line=start_line,
        start_column=ctx.char_column(start_line, node.col_offset),
        end_line=end_line,
        end_column=(
            ctx.char_column(end_line, node.end_col_offset)
            if node.end_col_offset is not None
            else None
        ),
    )
    func = ctx.enclosing_function(node)
    sink = ctx.masked_segment(node)  # secrets never enter a finding
    message = ctx.redact_masked_spans(match.message)
    return Finding(
        id="",
        vuln_class=classify(plugin.rule_id, plugin.cwe),
        rule_id=plugin.rule_id,
        severity=plugin.severity,
        location=region,
        message=message,
        snippet=_line_snippet(ctx, start_line, end_line),
        sink=sink,
        function=qualnames.get(id(func)) if func is not None else None,
        cwe=plugin.cwe,
        sources=(OWN_SOURCE,),
        confidence=match.confidence if match.confidence is not None else plugin.default_confidence,
        evidence=(Evidence(PRODUCER, "rule_match", f"{plugin.name}: {message}"),),
    )


def _line_snippet(ctx: FileContext, start: int, end: int, max_lines: int = 5) -> str:
    lines = ctx.masked_lines[start - 1 : min(end, start + max_lines - 1)]
    return "\n".join(lines)


def _qualnames(tree: ast.Module) -> dict[int, str]:
    """Map id(function node) -> dotted qualname (`Class.method`, `outer.<locals>.inner`)."""
    names: dict[int, str] = {}

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{child.name}"
                names[id(child)] = qual
                visit(child, f"{qual}.<locals>.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.Lambda):
                names[id(child)] = f"{prefix}<lambda>"
                visit(child, prefix)
            else:
                visit(child, prefix)

    visit(tree, "")
    return names
