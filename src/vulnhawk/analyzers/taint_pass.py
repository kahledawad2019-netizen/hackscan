"""Pass 2: intra-procedural taint analysis over candidate sinks.

For each function (and the module body) the statements are interpreted abstractly in
order. Every variable maps to a `Taint` value; branches are joined, loops iterate to a
fixpoint. When execution reaches a statement containing a candidate sink, the sink's
argument is evaluated in the current environment (joined over every visit).

Outcome per candidate (only for classes the engine models, see `TAINT_CLASSES`):
- provably constant              -> suppressed `taint:constant_input`
- sanitized for the finding class -> suppressed `taint:sanitized`
- reaches an untrusted source     -> confirmed, with a source trace
- otherwise (parameters, unknown calls, closures, imports) -> stays a candidate

Soundness stance: suppression only when *every* path yields constant/sanitized values;
anything the engine cannot model is `unknown`, which never suppresses.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace

from vulnhawk.core.models import Evidence, Finding, Status
from vulnhawk.core.taxonomy import TAINT_CLASSES
from vulnhawk.plugins.base import FileContext, Match
from vulnhawk.plugins.scopes import COMPREHENSION_TYPES, FUNCTION_TYPES
from vulnhawk.taint.sanitizers import SANITIZERS
from vulnhawk.taint.sources import (
    REQUEST_PARAM_ATTRS,
    REQUEST_PARAM_NAMES,
    SOURCE_NAMES,
    flask_request_source,
    is_route_handler,
)

PRODUCER = "taint"
CONSTANT_INPUT = "taint:constant_input"
SANITIZED = "taint:sanitized"
CONFIRMED_CONFIDENCE_BOOST = 35
MAX_LOOP_ITERATIONS = 5

# Methods that fold their arguments into the receiver (`parts.append(user)`).
MUTATORS = frozenset(
    {"append", "extend", "insert", "add", "update", "appendleft", "extendleft", "write"}
)
# Builtins that return a value derived only from their arguments.
PURE_BUILTINS = frozenset({"str", "repr", "format", "ascii", "bytes", "list", "tuple", "sorted"})


@dataclass(frozen=True, order=True)
class Source:
    line: int
    description: str


@dataclass(frozen=True)
class Taint:
    sources: frozenset[Source] = frozenset()
    unknown: bool = False
    safe_for: frozenset[str] = TAINT_CLASSES

    @property
    def is_constant(self) -> bool:
        return not self.sources and not self.unknown


CONST = Taint()
UNKNOWN = Taint(unknown=True, safe_for=frozenset())


def combine(values: Iterable[Taint]) -> Taint:
    """Value built from all of `values` (also the join of alternative paths)."""
    sources: set[Source] = set()
    unknown = False
    safe = set(TAINT_CLASSES)
    for v in values:
        sources |= v.sources
        unknown = unknown or v.unknown
        safe &= v.safe_for
    return Taint(frozenset(sources), unknown, frozenset(safe))


def source(description: str, node: ast.AST) -> Taint:
    return Taint(frozenset({Source(getattr(node, "lineno", 0), description)}), False, frozenset())


Env = dict[str, Taint]


def join_env(a: Env | None, b: Env | None) -> Env | None:
    if a is None:
        return None if b is None else dict(b)
    if b is None:
        return dict(a)
    out = dict(a)
    for k, v in b.items():
        out[k] = combine((out[k], v)) if k in out else v
    return out


# -- public API ---------------------------------------------------------------------------


def apply_taint(ctx: FileContext, candidates: list[tuple[Finding, Match]]) -> list[Finding]:
    """Return findings updated with taint results (same order; never drops any)."""
    targets = {
        id(m.node): m
        for f, m in candidates
        if f.vuln_class in TAINT_CLASSES and m.arg is not None and f.status is Status.CANDIDATE
    }
    if not targets:
        return [f for f, _ in candidates]
    engine = _FileEngine(ctx, targets)
    results = engine.run()
    return [_decide(f, results.get(id(m.node))) for f, m in candidates]


def _decide(finding: Finding, taint: Taint | None) -> Finding:
    if taint is None or finding.vuln_class not in TAINT_CLASSES:
        return finding
    if taint.is_constant:
        return replace(
            finding,
            status=Status.SUPPRESSED,
            suppression=CONSTANT_INPUT,
            confidence=0,
            evidence=(
                *finding.evidence,
                Evidence(PRODUCER, "taint_verdict", "Every path supplies a constant value."),
            ),
        )
    if finding.vuln_class in taint.safe_for:
        return replace(
            finding,
            status=Status.SUPPRESSED,
            suppression=SANITIZED,
            evidence=(
                *finding.evidence,
                Evidence(PRODUCER, "taint_verdict", "Every path is sanitized for this sink."),
            ),
        )
    if taint.sources:
        steps = tuple(
            Evidence(PRODUCER, "taint_step", f"Untrusted {s.description} at line {s.line}.")
            for s in sorted(taint.sources)
        )
        return replace(
            finding,
            status=Status.CONFIRMED,
            confidence=min(100, finding.confidence + CONFIRMED_CONFIDENCE_BOOST),
            evidence=(
                *finding.evidence,
                *steps,
                Evidence(PRODUCER, "taint_verdict", "Untrusted input reaches the sink."),
            ),
        )
    return replace(
        finding,
        evidence=(
            *finding.evidence,
            Evidence(
                PRODUCER,
                "taint_verdict",
                "Value origin not established within the function (parameter, call or "
                "non-local name); left for review.",
            ),
        ),
    )


# -- engine -------------------------------------------------------------------------------


class _FileEngine:
    def __init__(self, ctx: FileContext, targets: dict[int, Match]) -> None:
        self.ctx = ctx
        self.targets = targets
        self.results: dict[int, Taint] = {}
        self.module_constants: frozenset[str] = frozenset()

    def run(self) -> dict[int, Taint]:
        module = _FunctionEngine(self, self.ctx.tree, request_params=frozenset())
        module_env = module.run({})
        self.module_constants = self._constant_globals(module_env or {})
        for func in self._functions():
            if isinstance(func, ast.ClassDef):  # class body runs once, top to bottom
                _FunctionEngine(self, func, frozenset()).run({})
                continue
            params, request_params = self._initial_env(func)
            engine = _FunctionEngine(self, func, request_params)
            if isinstance(func, ast.Lambda):
                engine.visit_expression(func.body, params)
            else:
                engine.run(params)
        return self.results

    def record(self, call: ast.AST, value: Taint) -> None:
        prev = self.results.get(id(call))
        self.results[id(call)] = value if prev is None else combine((prev, value))

    def _functions(self) -> Iterator[ast.AST]:
        for node in ast.walk(self.ctx.tree):
            if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
                yield node

    def _constant_globals(self, module_env: Env) -> frozenset[str]:
        """Module names bound only to constants and never rebound via `global`."""
        rebound = {
            name
            for node in ast.walk(self.ctx.tree)
            if isinstance(node, ast.Global)
            for name in node.names
        }
        module_scope = self.ctx.scopes.module
        constants = set()
        for name, value in module_env.items():
            kinds = module_scope.bindings.get(name, set())
            if value.is_constant and name not in rebound and all(k == "local" for k, _ in kinds):
                constants.add(name)
        return frozenset(constants)

    def _initial_env(self, func: ast.AST) -> tuple[Env, frozenset[str]]:
        args = func.args  # type: ignore[attr-defined]
        names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
        names += [a.arg for a in (args.vararg, args.kwarg) if a is not None]
        route = is_route_handler(func)
        fname = getattr(func, "name", "<lambda>")
        env: Env = {}
        for name in names:
            if route and name not in {"self", "cls"} and name not in REQUEST_PARAM_NAMES:
                env[name] = source(f"route parameter `{name}` of handler `{fname}`", func)
            else:
                env[name] = UNKNOWN
        request_params = frozenset(n for n in names if n in REQUEST_PARAM_NAMES)
        return env, request_params


class _FunctionEngine:
    def __init__(self, file: _FileEngine, scope: ast.AST, request_params: frozenset[str]) -> None:
        self.file = file
        self.ctx = file.ctx
        self.scope = scope
        self.request_params = request_params
        self.is_module = isinstance(scope, ast.Module)

    # -- statements ------------------------------------------------------------------------

    def run(self, env: Env) -> Env | None:
        return self.exec_block(self.scope.body, dict(env))  # type: ignore[attr-defined]

    def visit_expression(self, expr: ast.AST, env: Env) -> None:
        self._check_sinks([expr], env)

    def exec_block(self, stmts: list[ast.stmt], env: Env | None) -> Env | None:
        for stmt in stmts:
            if env is None:
                return None
            env = self.exec_stmt(stmt, env)
        return env

    def exec_stmt(self, stmt: ast.stmt, env: Env) -> Env | None:
        self._check_sinks(_header_nodes(stmt), env)
        self._walrus(stmt, env)  # header `:=` bindings are visible to nested blocks

        if isinstance(stmt, ast.Assign):
            value = self.eval(stmt.value, env)
            for target in stmt.targets:
                self._assign(target, value, env)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._assign(stmt.target, self.eval(stmt.value, env), env)
        elif isinstance(stmt, ast.AugAssign):
            value = combine((self.eval(stmt.target, env), self.eval(stmt.value, env)))
            self._assign(stmt.target, value, env)
        elif isinstance(stmt, ast.Expr):
            self._mutation(stmt.value, env)
        elif isinstance(stmt, (ast.Return, ast.Raise)):
            return None
        elif isinstance(stmt, ast.If):
            then = self.exec_block(stmt.body, dict(env))
            other = self.exec_block(stmt.orelse, dict(env))
            return join_env(then, other)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self._loop(stmt, env, target=stmt.target, iter_=stmt.iter)
        elif isinstance(stmt, ast.While):
            return self._loop(stmt, env, target=None, iter_=None)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, self.eval(item.context_expr, env), env)
            return self.exec_block(stmt.body, env)
        elif isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
            return self._try(stmt, env)
        elif isinstance(stmt, ast.Match):
            subject = self.eval(stmt.subject, env)
            out: Env | None = dict(env)  # no case matched
            for case in stmt.cases:
                case_env = dict(env)
                for node in ast.walk(case.pattern):
                    name = getattr(node, "name", None)
                    if isinstance(name, str):
                        case_env[name] = subject
                out = join_env(out, self.exec_block(case.body, case_env))
            return out
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            env[stmt.name] = UNKNOWN
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                if alias.name != "*":
                    env[(alias.asname or alias.name).split(".")[0]] = UNKNOWN
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
        return env

    def _loop(self, stmt: ast.stmt, env: Env, target: ast.AST | None, iter_: ast.AST | None):
        item = self.eval(iter_, env) if iter_ is not None else None
        entry = dict(env)
        current: Env = dict(env)
        for _ in range(MAX_LOOP_ITERATIONS):
            body_env = dict(current)
            if target is not None and item is not None:
                self._assign(target, item, body_env)
            out = self.exec_block(stmt.body, body_env)  # type: ignore[attr-defined]
            if isinstance(stmt, ast.While):
                self._check_sinks([stmt.test], body_env if out is None else out)
            merged = join_env(current, out)
            if merged == current:
                break
            current = merged or current
        exit_env = join_env(entry, current)
        return self.exec_block(stmt.orelse, exit_env)  # type: ignore[attr-defined]

    def _try(self, stmt: ast.stmt, env: Env) -> Env | None:
        body_out = self.exec_block(stmt.body, dict(env))  # type: ignore[attr-defined]
        may_raise = join_env(env, body_out)
        outs: Env | None = self.exec_block(stmt.orelse, body_out)  # type: ignore[attr-defined]
        for handler in stmt.handlers:  # type: ignore[attr-defined]
            h_env = dict(may_raise or env)
            if handler.name:
                h_env[handler.name] = UNKNOWN
            outs = join_env(outs, self.exec_block(handler.body, h_env))
        final_in = outs if outs is not None else dict(may_raise or env)
        final = self.exec_block(stmt.finalbody, final_in)  # type: ignore[attr-defined]
        return final if outs is not None else None

    def _assign(self, target: ast.AST, value: Taint, env: Env) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, value, env)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, value, env)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = _base_name(target)
            if base is not None:  # weak update: obj.x = v / d[k] = v taints obj / d
                env[base] = combine((self._lookup(base, target, env), value))

    def _mutation(self, expr: ast.AST, env: Env) -> None:
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr in MUTATORS
            and isinstance(expr.func.value, ast.Name)
        ):
            name = expr.func.value.id
            args = [self.eval(a, env) for a in _call_args(expr)]
            env[name] = combine((self._lookup(name, expr.func.value, env), *args))

    def _walrus(self, stmt: ast.stmt, env: Env) -> None:
        for node in _same_scope_walk(_header_nodes(stmt)):
            if isinstance(node, ast.NamedExpr):
                env[node.target.id] = self.eval(node.value, env)

    def _check_sinks(self, nodes: list[ast.AST], env: Env) -> None:
        for node in _same_scope_walk(nodes):
            match = self.file.targets.get(id(node))
            if match is not None and match.arg is not None:
                self.file.record(node, self.eval(match.arg, env))

    # -- expressions -----------------------------------------------------------------------

    def eval(self, node: ast.AST | None, env: Env) -> Taint:
        if node is None:
            return CONST
        if isinstance(node, ast.Constant):
            return CONST
        if isinstance(node, ast.Name):
            return self._lookup(node.id, node, env)
        if isinstance(node, ast.Attribute):
            return self._attribute(node, env)
        if isinstance(node, ast.Subscript):
            return self.eval(node.value, env)
        if isinstance(node, ast.Call):
            return self._call(node, env)
        if isinstance(node, ast.Compare) or (
            isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
        ):
            return CONST  # booleans cannot carry injection payloads
        if isinstance(node, ast.IfExp):
            return combine((self.eval(node.body, env), self.eval(node.orelse, env)))
        if isinstance(node, ast.NamedExpr):
            return self.eval(node.value, env)
        if isinstance(node, COMPREHENSION_TYPES):
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            return combine(self.eval(p, env) for p in parts)
        if isinstance(node, (ast.Lambda, ast.Yield, ast.YieldFrom)):
            return UNKNOWN
        if isinstance(
            node,
            (
                ast.JoinedStr,
                ast.FormattedValue,
                ast.BinOp,
                ast.BoolOp,
                ast.UnaryOp,
                ast.Tuple,
                ast.List,
                ast.Set,
                ast.Dict,
                ast.Starred,
                ast.Await,
                ast.Slice,
            ),
        ):
            children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
            return combine(self.eval(c, env) for c in children) if children else CONST
        return UNKNOWN

    def _lookup(self, name: str, node: ast.AST, env: Env) -> Taint:
        if name in env:
            return env[name]
        comp = self._comprehension_binding(name, node, env)
        if comp is not None:
            return comp
        resolved = self.ctx.scopes.resolve_name(name, node)
        for qualified in resolved:
            if qualified in SOURCE_NAMES:
                return source(SOURCE_NAMES[qualified], node)
        if not self.is_module and name in self.file.module_constants:
            return CONST
        return UNKNOWN

    def _comprehension_binding(self, name: str, node: ast.AST, env: Env) -> Taint | None:
        scope = self.ctx.scopes.scope_of(node)
        while scope is not None and scope.is_comprehension:
            if name in scope.bindings:
                for gen in scope.node.generators:  # type: ignore[attr-defined]
                    if any(isinstance(t, ast.Name) and t.id == name for t in ast.walk(gen.target)):
                        return self.eval(gen.iter, env)
                return UNKNOWN
            scope = scope.parent
        return None

    def _attribute(self, node: ast.Attribute, env: Env) -> Taint:
        for qualified in self.ctx.resolve_all(node):
            description = flask_request_source(qualified) or SOURCE_NAMES.get(qualified)
            if description:
                return source(description, node)
        base = node.value
        if (
            isinstance(base, ast.Name)
            and base.id in self.request_params
            and node.attr in REQUEST_PARAM_ATTRS
        ):
            return source(f"request data (`{base.id}.{node.attr}`)", node)
        return self.eval(base, env)

    def _call(self, node: ast.Call, env: Env) -> Taint:
        names = self.ctx.call_names(node)
        args = [self.eval(a, env) for a in _call_args(node)]
        for qualified in names:
            if qualified in SOURCE_NAMES:
                return source(SOURCE_NAMES[qualified], node)
        safe: set[str] = set()
        for qualified in names:
            safe |= SANITIZERS.get(qualified, frozenset())
        if safe:
            value = combine(args) if args else CONST
            return Taint(value.sources, value.unknown, frozenset(value.safe_for | safe))
        if isinstance(node.func, ast.Attribute):
            # Methods derive their result from the receiver and arguments
            # (`request.args.get("q")`, `" ".join(parts)`, `template.format(x)`).
            return combine((self._attribute(node.func, env), *args))
        if names & PURE_BUILTINS:
            return combine(args) if args else CONST
        # Unknown function: taint flows through, but the result is not provably constant.
        return combine((UNKNOWN, *args))


# -- helpers ------------------------------------------------------------------------------


def _call_args(node: ast.Call) -> list[ast.expr]:
    return [*node.args, *(k.value for k in node.keywords)]


def _base_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _header_nodes(stmt: ast.stmt) -> list[ast.AST]:
    """Parts of `stmt` evaluated before any nested block runs."""
    if isinstance(stmt, (ast.If, ast.While)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [i.context_expr for i in stmt.items]
    if isinstance(stmt, ast.Match):
        return [stmt.subject]
    if isinstance(stmt, ast.Try) or type(stmt).__name__ == "TryStar":
        return []
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = stmt.args
        return [*stmt.decorator_list, *args.defaults, *(d for d in args.kw_defaults if d)]
    if isinstance(stmt, ast.ClassDef):
        return [*stmt.decorator_list, *stmt.bases, *(k.value for k in stmt.keywords)]
    return [stmt]


def _same_scope_walk(nodes: list[ast.AST]) -> Iterator[ast.AST]:
    """Walk `nodes` without entering function or class bodies (comprehensions included)."""
    stack = list(nodes)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))
