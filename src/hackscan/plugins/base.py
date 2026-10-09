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

from hackscan.core.models import Severity
from hackscan.plugins.scopes import ScopeIndex

_NEWLINE_RE = re.compile(r"\r\n|\r|\n")

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda

SQL_KEYWORD_RE = re.compile(
    r"^\s*(select|insert|update|delete|with|create|drop|alter|replace|merge|truncate|grant)\b"
    r"|\b(from|where|order\s+by|group\s+by|values|into|join|set)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Match:
    node: ast.AST  # the sink (reported location)
    message: str
    confidence: int | None = None  # None -> rule default
    # The value flowing into the sink (e.g. the query argument). When set and the rule's
    # class is modeled by the taint pass, taint decides confirm/suppress/keep.
    arg: ast.AST | None = None


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
    """Parsed file plus the lookups rules need: scoped name resolution and source text.

    Data-flow questions (is this variable constant/sanitized/tainted?) are deliberately
    *not* answered here: rules report candidates, the taint pass (M2) decides.
    """

    path: str  # POSIX, relative to scan root
    source: str
    tree: ast.Module
    lines: list[str] = field(init=False)
    scopes: ScopeIndex = field(init=False)
    _masked: list[str] | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        self.lines = _NEWLINE_RE.split(self.source)
        self.scopes = ScopeIndex(self.tree)
        self._masked = None

    # -- names -------------------------------------------------------------------------

    def resolve_all(self, expr: ast.AST) -> frozenset[str]:
        """Every dotted name `expr` may refer to (see `plugins.scopes`); empty if unknown."""
        if isinstance(expr, ast.Name):
            return self.scopes.resolve_name(expr.id, expr)
        if isinstance(expr, ast.Attribute):
            return frozenset(f"{base}.{expr.attr}" for base in self.resolve_all(expr.value))
        return frozenset()

    def call_names(self, call: ast.Call) -> frozenset[str]:
        return self.resolve_all(call.func)

    def resolve(self, expr: ast.AST) -> str | None:
        """Dotted name of `expr`, resolved in the scope where `expr` appears.

        `sp.run` after `import subprocess as sp` -> `subprocess.run`;
        `system` after `from os import system` -> `os.system`; builtins stay bare.
        Local values (parameters, assignments) resolve to None: `os.system` where `os`
        is a parameter is not the `os` module. When several names are possible (star
        imports, import fallbacks) this returns one deterministically; rules matching sinks
        should use `call_names` / `resolve_all`.
        """
        names = self.resolve_all(expr)
        return min(names) if names else None

    def call_name(self, call: ast.Call) -> str | None:
        return self.resolve(call.func)

    # -- scopes ------------------------------------------------------------------------

    def enclosing_function(self, node: ast.AST) -> FunctionNode | None:
        return self.scopes.enclosing_function(node)  # type: ignore[return-value]

    def assignments_before(self, name: str, node: ast.AST) -> list[ast.expr]:
        """Values assigned to local `name` textually before `node` in the same scope.

        Flow-insensitive: use only to *find* candidate values (e.g. a literal algorithm
        name), never to dismiss a finding.
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

    def binding_values(self, name: str, node: ast.AST) -> list[ast.expr]:
        """Values assigned to `name` in the scope it is bound in, as seen from `node`:
        local assignments before `node`, else all module-level assignments (module code
        runs before the function is called). Flow-insensitive: for *finding* candidates.
        """
        local = self.assignments_before(name, node)
        if local or self.enclosing_function(node) is None:
            return local
        values: list[ast.expr] = []
        for stmt in _walk_same_scope(self.tree):
            if isinstance(stmt, ast.Assign) and any(_binds(t, name) for t in stmt.targets):
                values.append(stmt.value)
        return values

    # -- source text -------------------------------------------------------------------

    def segment(self, node: ast.AST) -> str:
        return ast.get_source_segment(self.source, node) or ""

    def char_column(self, line: int, byte_offset: int) -> int:
        """Convert an AST UTF-8 byte offset to a 1-based character column."""
        text = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        prefix = text.encode("utf-8")[:byte_offset].decode("utf-8", errors="replace")
        return len(prefix) + 1

    @property
    def masked_lines(self) -> list[str]:
        """`lines` with string literals assigned to secret-looking names masked (same
        lines and character columns); what reports and the LLM get to see."""
        if self._masked is None:
            from hackscan.core.redact import mask_secret_literals

            self._masked = _NEWLINE_RE.split(mask_secret_literals(self.source, self.tree))
        return self._masked

    def masked_segment(self, node: ast.AST) -> str:
        return self._slice(self.masked_lines, node)

    def has_secret_literal(self, node: ast.AST) -> bool:
        """Whether `node`'s source contains a masked secret literal: then no fix is made,
        since a fix must carry the real code."""
        return self._slice(self.masked_lines, node) != self._slice(self.lines, node)

    def _slice(self, lines: list[str], node: ast.AST) -> str:
        start, end = node.lineno, node.end_lineno or node.lineno
        first = self.char_column(start, node.col_offset) - 1
        last = (
            self.char_column(end, node.end_col_offset) - 1
            if node.end_col_offset is not None
            else None
        )
        chunk = lines[start - 1 : end]
        if not chunk:
            return ""
        if len(chunk) == 1:
            return chunk[0][first:last]
        return "\n".join([chunk[0][first:], *chunk[1:-1], chunk[-1][:last]])


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


def is_string_formatting(expr: ast.AST) -> bool:
    """Looser than `is_dynamic_string`: also `%`/`.format()` applied to a template
    variable (`template % user`, `template.format(user)`). Only meaningful at sinks
    that expect a string, since `a % b` is also integer modulo."""
    if is_dynamic_string(expr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Mod):
        return not is_constant(expr.right)
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in {"format", "format_map"}
    ):
        return any(not is_constant(a) for a in [*expr.args, *(k.value for k in expr.keywords)])
    return False


def has_sql_text(expr: ast.AST) -> bool:
    """Any string literal inside `expr` that looks like SQL."""
    return any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and SQL_KEYWORD_RE.search(node.value)
        for node in ast.walk(expr)
    )


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def first_arg(call: ast.Call, kw: str | None = None) -> ast.expr | None:
    if call.args and not isinstance(call.args[0], ast.Starred):
        return call.args[0]
    return keyword(call, kw) if kw else None


# -- internals ----------------------------------------------------------------------------


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
