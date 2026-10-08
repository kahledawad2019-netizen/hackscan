"""Shared importer helpers: path/region normalization and enrichment from source.

Per the Finding contract, `sink` and `function` are derived from the parsed file (not
from a tool's display snippet), so fingerprints do not depend on which tool reported.
"""

from __future__ import annotations

import ast
import io
import tokenize
import warnings
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

from hackscan.analyzers.ast_pass import _qualnames
from hackscan.core.models import Region, Severity
from hackscan.plugins.base import FileContext


class ReportError(Exception):
    """A third-party report could not be read or run."""

    pass


@dataclass
class ImportResult:
    tool: str
    findings: list = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    secrets: set[str] = field(default_factory=set)  # values to redact from all output


def normalize_path(raw: str, root: Path, base_uri: str | None = None) -> str | None:
    """Tool-reported path/URI -> POSIX path relative to `root`, or None if outside it."""
    if raw.startswith("file:"):
        parsed = urlparse(raw)
        if parsed.netloc not in ("", "localhost"):
            return None  # file://other-host/share/... is not a local path
        raw = unquote(parsed.path)
        if len(raw) >= 3 and raw[0] == "/" and raw[2] == ":":  # file:///C:/x -> C:/x
            raw = raw[1:]
    else:
        raw = unquote(raw)
        if base_uri:
            base = normalize_path(base_uri, root) if base_uri.startswith("file:") else None
            if base is not None:
                raw = str(PurePosixPath(base) / raw)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        rel = candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return rel.as_posix()


def make_region(
    path: str,
    start_line: int | None,
    start_column: int | None = None,
    end_line: int | None = None,
    end_column: int | None = None,
) -> Region:
    """Region with the importer normalization rules (PROJECT.md):
    - missing end line -> start line; missing end column -> same as start (a point),
      so a column-precise report never silently widens to the rest of the line;
    - missing start column -> whole line;
    - invalid values are clamped rather than rejected (non-numbers raise ValueError).
    """
    line = max(1, int(start_line or 1))
    end = max(line, int(end_line or line))
    col = int(start_column) if start_column and int(start_column) > 0 else 1
    end_col = int(end_column) if end_column and int(end_column) > 0 else None
    if start_column is None or int(start_column) <= 0:
        end_col = None  # whole line
    elif end_col is None and end == line:
        end_col = col  # point at the reported start
    if end_col is not None and end == line and end_col < col:
        end_col = col
    return Region(path=path, start_line=line, start_column=col, end_line=end, end_column=end_col)


SEVERITY_FROM_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.LOW,
}


def severity_from_score(score: float) -> Severity:
    """CVSS-like `security-severity` (CodeQL, Semgrep) -> Severity."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class SourceIndex:
    """Lazily parsed project files for enriching imported findings."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._cache: dict[str, tuple[FileContext, dict[int, str]] | None] = {}

    def context(self, rel_path: str) -> tuple[FileContext, dict[int, str]] | None:
        if rel_path not in self._cache:
            self._cache[rel_path] = self._load(rel_path)
        return self._cache[rel_path]

    def _load(self, rel_path: str) -> tuple[FileContext, dict[int, str]] | None:
        path = self.root / rel_path
        if path.suffix != ".py":
            return None
        try:
            data = path.read_bytes()
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            source = data.decode(encoding)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(source)
        except (OSError, SyntaxError, UnicodeDecodeError, LookupError, ValueError):
            return None
        return FileContext(path=rel_path, source=source, tree=tree), _qualnames(tree)

    def line_text(self, rel_path: str, line: int) -> str:
        loaded = self.context(rel_path)
        if loaded is not None:
            lines = loaded[0].lines
            return lines[line - 1] if 0 < line <= len(lines) else ""
        try:
            lines = (self.root / rel_path).read_text(encoding="utf-8", errors="replace")
            split = lines.splitlines()
            return split[line - 1] if 0 < line <= len(split) else ""
        except OSError:
            return ""

    def enrich(self, region: Region) -> tuple[str, str | None]:
        """(sink text, enclosing function qualname) for a region in a Python file.

        The sink is the innermost call that starts on the region's first line and covers
        its start column (or the first call on that line for whole-line regions).
        """
        loaded = self.context(region.path)
        if loaded is None:
            return "", None
        ctx, qualnames = loaded
        best: ast.AST | None = None
        for node in ast.walk(ctx.tree):
            if not isinstance(node, ast.Call) or node.lineno != region.start_line:
                continue
            col = ctx.char_column(node.lineno, node.col_offset)
            end = (
                ctx.char_column(node.end_lineno, node.end_col_offset)
                if node.end_lineno == node.lineno and node.end_col_offset is not None
                else 10**9
            )
            if region.end_column is not None and not (col <= region.start_column < end):
                continue
            if best is None or (col, -end) > _span_key(ctx, best):
                best = node
        if best is None:
            line_text = (
                ctx.lines[region.start_line - 1] if region.start_line <= len(ctx.lines) else ""
            )
            func = _function_at_line(ctx, qualnames, region.start_line)
            return line_text.strip(), func
        func_node = ctx.enclosing_function(best)
        return ctx.segment(best), qualnames.get(id(func_node)) if func_node else None


def _span_key(ctx: FileContext, node: ast.AST) -> tuple[int, int]:
    col = ctx.char_column(node.lineno, node.col_offset)
    end = (
        ctx.char_column(node.end_lineno, node.end_col_offset)
        if node.end_lineno == node.lineno and node.end_col_offset is not None
        else 10**9
    )
    return col, -end


def _function_at_line(ctx: FileContext, qualnames: dict[int, str], line: int) -> str | None:
    best = None
    for node in ast.walk(ctx.tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno <= line <= (node.end_lineno or node.lineno)
            and (best is None or node.lineno >= best.lineno)
        ):
            best = node  # innermost: the latest-starting function containing the line
    return qualnames.get(id(best)) if best is not None else None
