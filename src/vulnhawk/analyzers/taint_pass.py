"""Pass 2: intra-procedural taint analysis over candidate sinks.

For each function (and the module and class bodies) the statements are interpreted
abstractly in order. Every variable maps to a `Taint` value; branches are joined, loops
iterate to a fixpoint. Within a statement, sub-expressions are scanned in evaluation
order, so `:=` bindings and container mutations take effect exactly where Python
applies them. When a candidate sink is reached, its argument is evaluated in the current
environment (joined over every visit).

Outcome per candidate (only for classes the engine models, see `TAINT_CLASSES`):
- provably constant              -> suppressed `taint:constant_input`
- sanitized for the finding class -> suppressed `taint:sanitized`
- reaches an untrusted source     -> confirmed, with a source trace
- otherwise (parameters, unknown calls, closures, imports) -> stays a candidate

Soundness stance: suppression only when *every* path yields constant/sanitized values.
Mutable values are tracked conservatively: a mutable object that is aliased, mutated,
passed to an unmodeled call, stored elsewhere or captured by a nested scope may change
behind the analysis' back, so it is joined with `unknown` at that point.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace

from vulnhawk.core.models import Evidence, Finding, Status
from vulnhawk.core.taxonomy import CMDI, TAINT_CLASSES
from vulnhawk.plugins.base import FileContext, Match
from vulnhawk.plugins.scopes import COMPREHENSION_TYPES, FUNCTION_TYPES
from vulnhawk.taint.sanitizers import QUOTING_SANITIZERS, SANITIZERS
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
POSIX_QUOTED_CONFIDENCE = 20
MAX_LOOP_ITERATIONS = 5

# Calls that neither mutate nor retain their arguments.
NON_ESCAPING_CALLS = frozenset(
    {
        "str",
        "repr",
        "format",
        "ascii",
        "bytes",
        "len",
        "print",
        "isinstance",
        "id",
        "hash",
        "bool",
        "int",
        "float",
        "sorted",
        "any",
        "all",
        "min",
        "max",
        "sum",
        "tuple",
        "list",
        "set",
        "frozenset",
        "dict",
    }
)
# Builtins whose result is derived only from their arguments.
PURE_BUILTINS = frozenset(
    {"str", "repr", "format", "ascii", "bytes", "tuple", "sorted", "frozenset"}
)
# Builtins returning a fresh mutable container built from their arguments.
MUTABLE_BUILTINS = frozenset({"list", "dict", "set", "bytearray"})
# String methods: result is a new immutable string derived from receiver and args.
STRING_METHODS = frozenset(
    {
        "join",
        "format",
        "format_map",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "title",
        "capitalize",
        "casefold",
        "replace",
        "encode",
        "decode",
        "removeprefix",
        "removesuffix",
        "zfill",
        "center",
        "ljust",
        "rjust",
        "expandtabs",
        "swapcase",
    }
)
# String-building methods whose receiver is a template (quote context applies).
TEMPLATE_METHODS = frozenset({"join", "format", "format_map"})
# Methods on a mutable receiver known not to modify it.
READONLY_METHODS = frozenset(
    {"count", "index", "copy", "get", "keys", "values", "items", "__len__", "__contains__"}
)
SHELL_QUOTE_CHARS = frozenset("'\"`")


@dataclass(frozen=True, order=True)
class Source:
    line: int
    description: str


@dataclass(frozen=True)
class Taint:
    sources: frozenset[Source] = frozenset()
    unknown: bool = False
    safe_for: frozenset[str] = TAINT_CLASSES
    # May refer to a mutable object (list/dict/set/...), which can change in place.
    mutable: bool = False
    # Text is known not to open a shell quote context: literals without quote characters,
    # numbers, or output of a quoting sanitizer (which is self-balanced).
    shell_plain: bool = True
    # Command-injection safety relies on a quoting sanitizer (context-sensitive).
    quote_sanitized: bool = False

    @property
    def is_constant(self) -> bool:
        return not self.sources and not self.unknown


CONST = Taint()
UNKNOWN = Taint(unknown=True, safe_for=frozenset(), mutable=True, shell_plain=False)


def combine(values: Iterable[Taint]) -> Taint:
    """Value derived from all of `values` (also the join of alternative paths)."""
    sources: set[Source] = set()
    unknown = mutable = quote_sanitized = False
    shell_plain = True
    safe = set(TAINT_CLASSES)
    for v in values:
        sources |= v.sources
        unknown = unknown or v.unknown
        safe &= v.safe_for
        mutable = mutable or v.mutable
        shell_plain = shell_plain and v.shell_plain
        quote_sanitized = quote_sanitized or v.quote_sanitized
    return Taint(
        frozenset(sources), unknown, frozenset(safe), mutable, shell_plain, quote_sanitized
    )


def concat(values: list[Taint]) -> Taint:
    """A string assembled from `values` (f-string, `+`, `%`, `.format`, `.join`).

    Shell quoting is context-sensitive: `'echo "' + shlex.quote(x) + '"'` puts the
    quoted value inside double quotes where `$(...)` still expands. If any part could
    open a quote context, quoting-based command-injection safety is dropped.
    """
    result = combine(values)
    if not result.shell_plain and any(v.quote_sanitized for v in values):
        result = replace(result, safe_for=result.safe_for - {CMDI})
    return replace(result, mutable=False)


def unquote(value: Taint) -> Taint:
    """Any transformation of a shell-quoted value (strip, replace, slicing, repr...) may
    break the quoting, so quoting-based safety does not survive it."""
    if not value.quote_sanitized:
        return value
    return replace(value, safe_for=value.safe_for - {CMDI}, quote_sanitized=False)


def literal(value: object) -> Taint:
    if isinstance(value, (str, bytes)):
        text = value if isinstance(value, str) else value.decode("latin-1")
        return Taint(shell_plain=not (SHELL_QUOTE_CHARS & set(text)))
    return CONST


def source(description: str, node: ast.AST) -> Taint:
    return Taint(
        frozenset({Source(getattr(node, "lineno", 0), description)}),
        safe_for=frozenset(),
        shell_plain=False,
    )


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
    if finding.vuln_class == CMDI and CMDI in taint.safe_for and taint.quote_sanitized:
        # shlex.quote protects POSIX shells only; under Windows cmd.exe `&`, `|` still
        # chain commands. The target platform is unknown, so keep it visible.
        return replace(
            finding,
            confidence=min(finding.confidence, POSIX_QUOTED_CONFIDENCE),
            evidence=(
                *finding.evidence,
                Evidence(
                    PRODUCER,
                    "taint_verdict",
                    "Shell-quoted with POSIX quoting (shlex.quote); safe on POSIX shells only.",
                ),
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
        """Module names bound only to immutable constants, never rebound via `global`."""
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
            if (
                value.is_constant
                and not value.mutable
                and name not in rebound
                and all(k == "local" for k, _ in kinds)
            ):
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
        # Flow-insensitive alias groups among names that may share a mutable object.
        self.groups: dict[str, set[str]] = {}
        self.closure_loads, self.closure_stores = _closure_names(scope)
        # States at which an exception may be raised / control may leave a `try` early;
        # one collector per active `try` statement.
        self.try_states: list[list[Env]] = []

    # -- statements ------------------------------------------------------------------------

    def run(self, env: Env) -> Env | None:
        return self.exec_block(self.scope.body, dict(env))  # type: ignore[attr-defined]

    def visit_expression(self, expr: ast.AST, env: Env) -> None:
        self._scan(expr, env)

    def exec_block(self, stmts: list[ast.stmt], env: Env | None) -> Env | None:
        for stmt in stmts:
            if env is None:
                return None
            env = self.exec_stmt(stmt, env)
        return env

    def exec_stmt(self, stmt: ast.stmt, env: Env) -> Env | None:
        if self.try_states:  # any statement may raise (or return) from here
            self.try_states[-1].append(dict(env))
        for node in _header_nodes(stmt):
            self._scan(node, env)
        if self.try_states and isinstance(stmt, (ast.Return, ast.Raise)):
            self.try_states[-1].append(dict(env))  # after evaluating e.g. `return x := ...`

        if isinstance(stmt, ast.Assign):
            value = self.eval(stmt.value, env)
            for target in stmt.targets:
                self._assign(target, value, env, stmt.value)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._assign(stmt.target, self.eval(stmt.value, env), env, stmt.value)
        elif isinstance(stmt, ast.AugAssign):
            current = self.eval(stmt.target, env)
            value = combine((current, self.eval(stmt.value, env)))
            if current.mutable and isinstance(stmt.target, ast.Name):
                self._weak_update(stmt.target.id, value, env)  # in-place `+=` on lists
            else:
                self._assign(stmt.target, value, env, None)
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
                    value = self.eval(item.context_expr, env)
                    self._assign(item.optional_vars, value, env, item.context_expr)
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
                if case.guard is not None:
                    self._scan(case.guard, case_env)
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
        entry = dict(env)
        current: Env = dict(env)
        for _ in range(MAX_LOOP_ITERATIONS):
            body_env = dict(current)
            if target is not None and iter_ is not None:
                self._assign(target, self.eval(iter_, body_env), body_env, iter_)
            out = self.exec_block(stmt.body, body_env)  # type: ignore[attr-defined]
            if isinstance(stmt, ast.While) and out is not None:
                self._scan(stmt.test, out)  # condition re-evaluated each iteration
            merged = join_env(current, out)
            if merged == current:
                break
            current = merged or current
        else:  # no fixpoint within the budget: give up precision, stay sound
            current = {k: combine((v, UNKNOWN)) for k, v in current.items()}
        exit_env = join_env(entry, current)
        return self.exec_block(stmt.orelse, exit_env)  # type: ignore[attr-defined]

    def _try(self, stmt: ast.stmt, env: Env) -> Env | None:
        # Handlers can be entered from any point in the body, so they see the join of
        # every state the body passed through (including just before a raise/return).
        self.try_states.append([dict(env)])
        body_out = self.exec_block(stmt.body, dict(env))  # type: ignore[attr-defined]
        raise_points = list(self.try_states[-1])
        outs: Env | None = self.exec_block(stmt.orelse, body_out)  # type: ignore[attr-defined]
        handler_entry: Env | None = None
        for state in [*raise_points, body_out]:
            handler_entry = join_env(handler_entry, state)
        for handler in stmt.handlers:  # type: ignore[attr-defined]
            h_env = dict(handler_entry or env)
            if handler.name:
                h_env[handler.name] = UNKNOWN
            outs = join_env(outs, self.exec_block(handler.body, h_env))
        leave_points = self.try_states.pop()  # body + orelse + handlers
        if self.try_states:  # an enclosing try sees these states too
            self.try_states[-1].extend(leave_points)
        # `finally` runs on normal exit and on every early exit (raise/return/break).
        final_in: Env | None = outs
        for state in leave_points:
            final_in = join_env(final_in, state)
        final = self.exec_block(stmt.finalbody, final_in or dict(env))  # type: ignore[attr-defined]
        return final if outs is not None else None

    def _assign(self, target: ast.AST, value: Taint, env: Env, value_expr: ast.AST | None):
        if isinstance(target, ast.Name):
            env[target.id] = value
            if value_expr is not None:
                for name in self._mutable_names_in(value_expr, env):
                    self._union(target.id, name)  # alias = parts / x = [parts] / row = rows[0]
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, value, env, value_expr)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, value, env, value_expr)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = _base_name(target)
            if base is not None:  # obj.x = v / d[k] = v: weak update of the container
                self._weak_update(base, value, env)
            if value_expr is not None:  # storing a mutable elsewhere lets it escape
                for name in self._mutable_names_in(value_expr, env):
                    self._weak_update(name, UNKNOWN, env)

    # -- in-order scan: sinks, walrus, mutation and escape -------------------------------

    def _scan(self, node: ast.AST, env: Env) -> None:
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                for part in _header_nodes(node):
                    self._scan(part, env)
            return
        for child in ast.iter_child_nodes(node):
            self._scan(child, env)
        if isinstance(node, ast.NamedExpr):
            self._assign(node.target, self.eval(node.value, env), env, node.value)
        elif isinstance(node, ast.Call):
            match = self.file.targets.get(id(node))
            if match is not None and match.arg is not None:
                self.file.record(node, self.eval(match.arg, env))
            self._call_effects(node, env)

    def _call_effects(self, call: ast.Call, env: Env) -> None:
        args = _call_args(call)
        func = call.func
        # Mutating method on a mutable receiver: `parts.append(x)`, `d.setdefault(k, x)`.
        if isinstance(func, ast.Attribute) and func.attr not in READONLY_METHODS:
            base = _base_name(func.value)
            if base is not None and self._lookup(base, func.value, env).mutable:
                self._weak_update(base, combine(self.eval(a, env) for a in args), env)
        # Mutable arguments escaping into code we do not model may be changed by it.
        names = self.ctx.call_names(call)
        is_string_method = (
            isinstance(func, ast.Attribute)
            and func.attr in STRING_METHODS
            and not self.eval(func.value, env).mutable
        )
        if names & (NON_ESCAPING_CALLS | SANITIZERS.keys()) or is_string_method:
            return
        for arg in args:
            for name in self._mutable_names_in(arg, env):
                self._weak_update(name, UNKNOWN, env)

    # -- aliasing ------------------------------------------------------------------------

    def _group(self, name: str) -> set[str]:
        return self.groups.get(name, {name})

    def _union(self, a: str, b: str) -> None:
        merged = self._group(a) | self._group(b)
        for n in merged:
            self.groups[n] = merged

    def _weak_update(self, name: str, value: Taint, env: Env) -> None:
        for n in self._group(name):
            if n in env:
                env[n] = combine((env[n], value))

    def _mutable_names_in(self, expr: ast.AST, env: Env) -> list[str]:
        """Local names anywhere in `expr` that may hold a mutable object. Calls are included:
        `dict(cmd=parts)` or `wrap(parts)` may keep a reference to `parts`."""
        out = []
        stack = [expr]
        while stack:
            node = stack.pop()
            if isinstance(node, ast.Name) and node.id in env and env[node.id].mutable:
                out.append(node.id)
            elif not isinstance(node, FUNCTION_TYPES):
                stack.extend(ast.iter_child_nodes(node))
        return out

    # -- expressions -----------------------------------------------------------------------

    def eval(self, node: ast.AST | None, env: Env) -> Taint:
        if node is None:
            return CONST
        if isinstance(node, ast.Constant):
            return literal(node.value)
        if isinstance(node, ast.Name):
            return self._lookup(node.id, node, env)
        if isinstance(node, ast.Attribute):
            return self._attribute(node, env)
        if isinstance(node, ast.Subscript):
            return unquote(self.eval(node.value, env))  # slicing can strip the quotes
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
        if isinstance(node, ast.JoinedStr):
            return concat([self.eval(v, env) for v in node.values])
        if isinstance(node, ast.FormattedValue):
            return self.eval(node.value, env)
        if isinstance(node, ast.BinOp):
            left, right = self.eval(node.left, env), self.eval(node.right, env)
            if isinstance(node.op, (ast.Add, ast.Mod)) and not (left.mutable or right.mutable):
                return concat([left, right])  # string building (or arithmetic: harmless)
            return combine((left, right))
        if isinstance(node, COMPREHENSION_TYPES):
            parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
            value = combine(self.eval(p, env) for p in parts)
            return replace(value, mutable=not isinstance(node, ast.GeneratorExp) or value.mutable)
        if isinstance(node, (ast.List, ast.Set, ast.Dict)):
            children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
            return replace(combine(self.eval(c, env) for c in children), mutable=True)
        if isinstance(node, (ast.Lambda, ast.Yield, ast.YieldFrom)):
            return UNKNOWN
        if isinstance(
            node, (ast.BoolOp, ast.UnaryOp, ast.Tuple, ast.Starred, ast.Await, ast.Slice)
        ):
            children = [c for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr)]
            return combine(self.eval(c, env) for c in children) if children else CONST
        return UNKNOWN

    def _lookup(self, name: str, node: ast.AST, env: Env) -> Taint:
        if name in env:
            value = env[name]
            if name in self.closure_stores or (name in self.closure_loads and value.mutable):
                return combine((value, UNKNOWN))  # a nested scope may change it
            return value
        comp = self._comprehension_binding(name, node, env)
        if comp is not None:
            return comp
        for qualified in self.ctx.scopes.resolve_name(name, node):
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
        if node.attr in REQUEST_PARAM_ATTRS and self._is_request_object(base):
            return source(f"request data (`{self.ctx.segment(node)}`)", node)
        return self.eval(base, env)

    def _is_request_object(self, expr: ast.AST) -> bool:
        """`request` parameter, or `self.request` (Django/DRF class-based views)."""
        if isinstance(expr, ast.Name):
            return expr.id in self.request_params
        return (
            isinstance(expr, ast.Attribute)
            and expr.attr in REQUEST_PARAM_NAMES
            and isinstance(expr.value, ast.Name)
            and expr.value.id in {"self", "cls"}
        )

    def _call(self, node: ast.Call, env: Env) -> Taint:
        names = self.ctx.call_names(node)
        args = [self.eval(a, env) for a in _call_args(node)]
        for qualified in names:
            if qualified in SOURCE_NAMES:
                return source(SOURCE_NAMES[qualified], node)
        safe: set[str] = set()
        quoting = False
        for qualified in names:
            safe |= SANITIZERS.get(qualified, frozenset())
            quoting = quoting or qualified in QUOTING_SANITIZERS
        if safe:
            value = combine(args) if args else CONST
            return Taint(
                value.sources,
                value.unknown,
                frozenset(value.safe_for | safe),
                mutable=False,
                shell_plain=True if quoting else value.shell_plain,
                quote_sanitized=quoting or value.quote_sanitized,
            )
        func = node.func
        if isinstance(func, ast.Attribute):
            # Methods derive their result from the receiver and arguments
            # (`request.args.get("q")`, `" ".join(parts)`, `template.format(x)`).
            receiver = self._attribute(func, env)
            if func.attr in TEMPLATE_METHODS:
                return concat([receiver, *args])
            if func.attr in STRING_METHODS:
                value = replace(combine((receiver, *args)), mutable=False)
                return value if func.attr in {"encode", "decode"} else unquote(value)
            return unquote(combine((receiver, *args)))
        if names & MUTABLE_BUILTINS:
            return replace(combine(args) if args else CONST, mutable=True)
        if names & PURE_BUILTINS:
            value = combine(args) if args else CONST
            return value if names == {"str"} else unquote(value)  # repr() adds quotes
        # Unknown function: taint flows through, but the result is not provably constant.
        return combine((UNKNOWN, *args))


# -- helpers ------------------------------------------------------------------------------


def _call_args(node: ast.Call) -> list[ast.expr]:
    return [*node.args, *(k.value for k in node.keywords)]


def _base_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _closure_names(scope: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """Names nested scopes inside `scope` read, and names they rebind (nonlocal/global)."""
    loads: set[str] = set()
    stores: set[str] = set()
    for node in ast.walk(scope):
        if node is scope or not isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name):
                loads.add(inner.id)
            elif isinstance(inner, ast.Nonlocal) or (
                isinstance(inner, ast.Global) and isinstance(scope, ast.Module)
            ):
                stores.update(inner.names)
    return frozenset(loads), frozenset(stores)


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
