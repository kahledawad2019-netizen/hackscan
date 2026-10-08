"""Rule plugin interface and the per-file context rules query.

A rule declares which AST node types it inspects and yields `Match`es for sink nodes.
The AST pass turns matches into `Finding`s (location, sink text, enclosing function,
vuln_class), so rules only decide *whether* a node is a candidate and how confident.
"""

from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from vulnhawk.core.models import Severity

_NEWLINE_RE = re.compile(r"\r\n|\r|\n")

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


@dataclass(frozen=True)
class Match:
    node: ast.AST
    message: str
    confidence: int | None = None  # None -> rule default


class RulePlugin(ABC):
    rule_id: str
    name: str
    description: str
    severity: Severity
    cwe: tuple[str, ...] = ()
    default_confidence: int = 50
    node_types: tuple[type[ast.AST], ...] = (ast.Call,)

    @abstractmethod
    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        """Yield matches for `node` (one of `node_types`)."""


@dataclass
class FileContext:
    """Parsed file plus the lookups rules need: import aliases, scopes, local assignments."""

    path: str  # POSIX, relative to scan root
    source: str
    tree: ast.Module
    lines: list[str] = field(init=False)
    aliases: dict[str, str] = field(init=False)
    _scopes: dict[int, FunctionNode | None] = field(init=False)

    def __post_init__(self) -> None:
        self.lines = _NEWLINE_RE.split(self.source)
        self.aliases = _collect_aliases(self.tree)
        self._scopes = {}
        _index_scopes(self.tree, None, self._scopes)

    # -- names -------------------------------------------------------------------------

    def resolve(self, expr: ast.AST) -> str | None:
        """Dotted name of `expr` with import aliases expanded.

        `sp.run` after `import subprocess as sp` -> `subprocess.run`;
        `system` after `from os import system` -> `os.system`; builtins stay bare.
        """
        if isinstance(expr, ast.Name):
            return self.aliases.get(expr.id, expr.id)
        if isinstance(expr, ast.Attribute):
            base = self.resolve(expr.value)
            return f"{base}.{expr.attr}" if base else None
        return None

    def call_name(self, call: ast.Call) -> str | None:
        return self.resolve(call.func)

    # -- scopes ------------------------------------------------------------------------

    def enclosing_function(self, node: ast.AST) -> FunctionNode | None:
        return self._scopes.get(id(node))

    def assignments_before(self, name: str, node: ast.AST) -> list[ast.expr]:
        """Values assigned to local `name` before `node`, in the same function (or module).

        Includes `x = ...`, `x += ...` (the right-hand side) and annotated assignments.
        Nested function bodies are excluded.
        """
        scope = self.enclosing_function(node) or self.tree
        line = getattr(node, "lineno", 0)
        values: list[ast.expr] = []
        for stmt in _walk_same_scope(scope):
            if getattr(stmt, "lineno", line) >= line:
                continue
            if isinstance(stmt, ast.Assign):
                if any(_binds(t, name) for t in stmt.targets):
                    values.append(stmt.value)
            elif (
                isinstance(stmt, (ast.AugAssign, ast.AnnAssign))
                and _binds(stmt.target, name)
                and stmt.value is not None
            ):
                values.append(stmt.value)
        return values

    def is_parameter(self, name: str, node: ast.AST) -> bool:
        func = self.enclosing_function(node)
        if func is None:
            return False
        args = func.args
        all_args = [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]
        return any(a is not None and a.arg == name for a in all_args)

    # -- source text -------------------------------------------------------------------

    def segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or ""

    def char_column(self, line: int, byte_offset: int) -> int:
        """Convert an AST UTF-8 byte offset to a 1-based character column."""
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        prefix = text.encode("utf-8")[:byte_offset].decode("utf-8", errors="replace")
        return len(prefix) + 1


# -- expression classification helpers (shared by rules) ----------------------------------


def is_constant(expr: ast.AST) -> bool:
    """True for expressions whose value is fixed at write time."""
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in expr.values)
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        return all(is_constant(e) for e in expr.elts)
    if isinstance(expr, ast.BinOp):
        return is_constant(expr.left) and is_constant(expr.right)
    return False


def _is_str_literal(expr: ast.AST) -> bool:
    return isinstance(expr, ast.JoinedStr) or (
        isinstance(expr, ast.Constant) and isinstance(expr.value, str)
    )


def _flatten_add(expr: ast.AST) -> Iterator[ast.AST]:
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        yield from _flatten_add(expr.left)
        yield from _flatten_add(expr.right)
    else:
        yield expr


def is_dynamic_string(expr: ast.AST) -> bool:
    """String built from non-constant parts: f-string, `%`, `+`, `.format()`, `.join()`."""
    if isinstance(expr, ast.JoinedStr):
        return not is_constant(expr)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return _is_str_literal(expr.left) and not is_constant(expr.right)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        parts = list(_flatten_add(expr))
        has_str = any(_is_str_literal(p) or is_dynamic_string(p) for p in parts)
        return has_str and not all(is_constant(p) for p in parts)
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in {"format", "join", "format_map"}
        and _is_str_literal(expr.func.value)
    ):
        args = [*expr.args, *(k.value for k in expr.keywords)]
        return any(not is_constant(a) for a in args)
    return False


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def first_arg(call: ast.Call, kw: str | None = None) -> ast.expr | None:
    if call.args and not isinstance(call.args[0], ast.Starred):
        return call.args[0]
    return keyword(call, kw) if kw else None


# -- internals ----------------------------------------------------------------------------


def _collect_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                if a.name != "*":
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _index_scopes(
    node: ast.AST, current: FunctionNode | None, out: dict[int, FunctionNode | None]
) -> None:
    for child in ast.iter_child_nodes(node):
        out[id(child)] = current
        inner = (
            child
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            else current
        )
        _index_scopes(child, inner, out)


def _walk_same_scope(scope: ast.AST) -> Iterator[ast.AST]:
    """Walk `scope` without descending into nested functions or classes."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _binds(target: ast.AST, name: str) -> bool:
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_binds(t, name) for t in target.elts)
    return False
