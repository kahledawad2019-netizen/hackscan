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

from hackscan.analyzers.interproc import (
    CallSite,
    FileFacts,
    Flow,
    FunctionFacts,
    SymbolPair,
    finding_key,
    linkable_functions,
    module_name,
    module_symbols,
    outer_parts,
    parameters,
)
from hackscan.core.models import Evidence, Finding, Status
from hackscan.core.taxonomy import CMDI, TAINT_CLASSES
from hackscan.plugins.base import FileContext, Match
from hackscan.plugins.scopes import COMPREHENSION_TYPES, FUNCTION_TYPES
from hackscan.taint.sanitizers import QUOTING_SANITIZERS, SANITIZERS
from hackscan.taint.sources import (
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
    # Symbolic parts for inter-procedural linking (see `interproc`): parameters and call
    # results this value may come from, each with the classes it was sanitized for.
    # They never affect the verdict of this pass.
    symbols: frozenset[SymbolPair] = frozenset()

    @property
    def is_constant(self) -> bool:
        return not self.sources and not self.unknown


CONST = Taint()
UNKNOWN = Taint(unknown=True, safe_for=frozenset(), mutable=True, shell_plain=False)


def combine(values: Iterable[Taint]) -> Taint:
    """Value derived from all of `values` (also the join of alternative paths)."""
    sources: set[Source] = set()
    symbols: set[SymbolPair] = set()
    unknown = mutable = quote_sanitized = False
    shell_plain = True
    safe = set(TAINT_CLASSES)
    for v in values:
        sources |= v.sources
        symbols |= v.symbols
        unknown = unknown or v.unknown
        safe &= v.safe_for
        mutable = mutable or v.mutable
        shell_plain = shell_plain and v.shell_plain
        quote_sanitized = quote_sanitized or v.quote_sanitized
    return Taint(
        frozenset(sources),
        unknown,
        frozenset(safe),
        mutable,
        shell_plain,
        quote_sanitized,
        frozenset(symbols),
    )


def _unsafe_symbols(value: Taint, classes: frozenset[str]) -> Taint:
    """Drop `classes` from what the symbolic parts count as sanitized for."""
    if not value.symbols:
        return value
    return replace(value, symbols=frozenset((a, s - classes) for a, s in value.symbols))


def _with_symbol(value: Taint, atom: tuple) -> Taint:
    return replace(value, symbols=value.symbols | {(atom, frozenset())})


def concat(values: list[Taint]) -> Taint:
    """A string assembled from `values` (f-string, `+`, `%`, `.format`, `.join`).

    Shell quoting is context-sensitive: `'echo "' + shlex.quote(x) + '"'` puts the
    quoted value inside double quotes where `$(...)` still expands. If any part could
    open a quote context, quoting-based command-injection safety is dropped.
    """
    result = combine(values)
    if not result.shell_plain and any(v.quote_sanitized for v in values):
        result = replace(result, safe_for=result.safe_for - {CMDI})
        result = _unsafe_symbols(result, frozenset({CMDI}))
    return replace(result, mutable=False)


def unquote(value: Taint) -> Taint:
    """Any transformation of a shell-quoted value (strip, replace, slicing, repr...) may
    break the quoting, so quoting-based safety does not survive it."""
    if not value.quote_sanitized:
        return value
    value = _unsafe_symbols(value, frozenset({CMDI}))
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
    return analyze_taint(ctx, candidates, link=False)[0]


def analyze_taint(
    ctx: FileContext, candidates: list[tuple[Finding, Match]], *, link: bool = True
) -> tuple[list[Finding], FileFacts | None]:
    """Like `apply_taint`; with `link`, also return this file's inter-procedural facts."""
    targets = {
        id(m.node): m
        for f, m in candidates
        if f.vuln_class in TAINT_CLASSES and m.arg is not None and f.status is Status.CANDIDATE
    }
    if not targets and not link:
        return [f for f, _ in candidates], None
    facts = FileFacts(ctx.path, module_name(ctx.path)) if link else None
    engine = _FileEngine(ctx, targets, facts)
    results = engine.run()
    findings = []
    for f, m in candidates:
        taint = results.get(id(m.node))
        decided = _decide(f, taint)
        if (
            facts is not None
            and taint is not None
            and taint.symbols
            and decided.status is Status.CANDIDATE
        ):
            facts.sinks[finding_key(decided)] = _flow(ctx, taint)
        findings.append(decided)
    return findings, facts


def _flow(ctx: FileContext, value: Taint) -> Flow:
    return Flow(
        frozenset((ctx.path, s.line, s.description) for s in value.sources),
        value.safe_for,
        value.symbols,
    )


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
    def __init__(
        self, ctx: FileContext, targets: dict[int, Match], facts: FileFacts | None = None
    ) -> None:
        self.ctx = ctx
        self.targets = targets
        self.results: dict[int, Taint] = {}
        self.module_constants: frozenset[str] = frozenset()
        self.facts = facts
        # `globals()`, `exec`, `__dict__`...: module names may change behind our back.
        self.namespace = _Namespace(ctx.tree)
        self.namespace_exposed = self.namespace.module
        self.linked: dict[int, str] = {}  # id(def) -> name, for linkable functions
        self._call_targets: dict[int, str | None] = {}
        self._sites: dict[tuple[int, int], tuple[str, int, list[Taint], dict[str, Taint]]] = {}
        if facts is not None:
            facts.symbols = module_symbols(ctx.tree, ctx.path)
            for func in linkable_functions(ctx.tree, facts.symbols):
                self.linked[id(func)] = func.name  # type: ignore[attr-defined]

    def run(self) -> dict[int, Taint]:
        module = _FunctionEngine(self, self.ctx.tree, request_params=frozenset())
        module_env = module.run({})
        if not module.has_walrus:  # see `_FunctionEngine.has_walrus`
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
            if self.facts is not None and id(func) in self.linked:
                positional, keyword = parameters(func)  # type: ignore[arg-type]
                returns = engine.returns
                self.facts.functions[self.linked[id(func)]] = FunctionFacts(
                    positional,
                    keyword,
                    _flow(self.ctx, returns) if returns is not None else None,
                )
        if self.facts is not None:
            for key, (target, line, positional, keywords) in sorted(self._sites.items()):
                self.facts.sites[key] = CallSite(
                    target,
                    line,
                    tuple(_flow(self.ctx, v) for v in positional),
                    tuple(sorted((k, _flow(self.ctx, v)) for k, v in keywords.items())),
                )
        return self.results

    def record(self, call: ast.AST, value: Taint) -> None:
        prev = self.results.get(id(call))
        self.results[id(call)] = value if prev is None else combine((prev, value))

    def call_target(self, call: ast.Call) -> str | None:
        """Absolute dotted name of a module-level callee, when it can be named statically."""
        if self.facts is None:
            return None
        if id(call) not in self._call_targets:
            self._call_targets[id(call)] = self._resolve_target(call)
        return self._call_targets[id(call)]

    def _resolve_target(self, call: ast.Call) -> str | None:
        assert self.facts is not None
        parts: list[str] = []
        func = call.func
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name) or not self.module_owned(func.id, call):
            return None
        entry = self.facts.symbols.get(func.id)
        if entry is None:
            return None
        kind, target = entry
        base = f"{self.facts.module}.{target}" if kind == "def" else target
        return ".".join([base, *reversed(parts)])

    def module_owned(self, name: str, node: ast.AST) -> bool:
        """Whether `name` at `node` refers to the module-level binding."""
        scope = self.ctx.scopes.scope_of(node)
        first = True
        while scope is not None:
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent
                continue
            first = False
            if name in scope.globals_:
                return True
            if name in scope.nonlocals or name in scope.bindings:
                return scope is self.ctx.scopes.module
            scope = scope.parent
        return False

    def record_site(self, call: ast.Call, positional: list[Taint], keywords: dict[str, Taint]):
        target = self.call_target(call)
        if target is None:
            return
        key = (call.lineno, call.col_offset)
        prev = self._sites.get(key)
        if prev is not None:
            n = min(len(prev[2]), len(positional))
            positional = [combine((a, b)) for a, b in zip(prev[2][:n], positional[:n], strict=True)]
            keywords = {
                k: combine((v, prev[3][k])) if k in prev[3] else v for k, v in keywords.items()
            } | {k: v for k, v in prev[3].items() if k not in keywords}
        self._sites[key] = (target, call.lineno, positional, keywords)

    def _functions(self) -> Iterator[ast.AST]:
        for node in ast.walk(self.ctx.tree):
            if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
                yield node

    def _constant_globals(self, module_env: Env) -> frozenset[str]:
        """Module names bound exactly once, to an immutable constant, never rebound via
        `global` and with no way to write the module namespace dynamically. (A function
        may run before a later rebinding, so the final value alone proves nothing.)"""
        if self.namespace_exposed:
            return frozenset()
        rebound = {
            name
            for node in ast.walk(self.ctx.tree)
            if isinstance(node, ast.Global)
            for name in node.names
        }
        counts = _module_binding_counts(self.ctx.tree)
        module_scope = self.ctx.scopes.module
        constants = set()
        for name, value in module_env.items():
            kinds = module_scope.bindings.get(name, set())
            if (
                value.is_constant
                and not value.mutable
                and name not in rebound
                and counts.get(name) == 1
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
        linked = self.linked.get(id(func))
        env: Env = {}
        for name in names:
            if route and name not in {"self", "cls"} and name not in REQUEST_PARAM_NAMES:
                env[name] = source(f"route parameter `{name}` of handler `{fname}`", func)
            elif linked is not None:
                env[name] = _with_symbol(UNKNOWN, ("param", self.ctx.path, linked, name))
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
        # States at `break` / `continue`, one collector per active loop.
        self.break_states: list[list[Env]] = []
        self.continue_states: list[list[Env]] = []
        # Join of every returned value (linkable functions only).
        self.track_returns = id(scope) in file.linked
        self.returns: Taint | None = None
        # `:=` can rebind a name mid-expression, conditionally (short-circuits, chained
        # comparisons, `assert` messages, comprehension filters) or after an operand was
        # already evaluated. Statements are interpreted as a whole, so in a scope with its
        # own `:=` no sink is ever suppressed (confirmation still works).
        self.has_walrus = _has_own_walrus(scope) or (
            (self.is_module and file.namespace_exposed)
            # `locals()` in a class body writes the real class namespace.
            or (isinstance(scope, ast.ClassDef) and file.namespace.class_body(scope))
        )
        self.class_body = isinstance(scope, ast.ClassDef)
        self.shared = _declared_shared(scope)
        # >0 while scanning code that runs later (a generator expression's body).
        self.deferred = 0

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
            if self.track_returns and isinstance(stmt, ast.Return) and stmt.value is not None:
                value = self.eval(stmt.value, env)
                self.returns = value if self.returns is None else combine((self.returns, value))
            return None
        elif isinstance(stmt, ast.Break):
            if self.break_states:
                self.break_states[-1].append(dict(env))
            return None  # statements after `break` do not run on this path
        elif isinstance(stmt, ast.Continue):
            if self.continue_states:
                self.continue_states[-1].append(dict(env))
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
            # A failed pattern or a false guard may leave captures bound, so later cases
            # and the no-match path see them too.
            fall: Env = dict(env)
            out: Env | None = None
            for case in stmt.cases:
                case_env = dict(fall)
                for node in ast.walk(case.pattern):
                    name = getattr(
                        node, "rest" if isinstance(node, ast.MatchMapping) else "name", None
                    )
                    if isinstance(name, str):
                        # The capture may be (part of) the subject object: alias them.
                        target = ast.Name(id=name, ctx=ast.Store())
                        self._assign(target, subject, case_env, stmt.subject)
                if case.guard is not None:
                    self._scan(case.guard, case_env)
                fall = join_env(fall, case_env) or fall
                out = join_env(out, self.exec_block(case.body, dict(case_env)))
            return join_env(out, fall)
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
        breaks: list[Env] = []
        for _ in range(MAX_LOOP_ITERATIONS):
            body_env = dict(current)
            if target is not None and iter_ is not None:
                self._assign(target, self.eval(iter_, body_env), body_env, iter_)
            self.break_states.append([])
            self.continue_states.append([])
            try:
                out = self.exec_block(stmt.body, body_env)  # type: ignore[attr-defined]
            finally:
                breaks.extend(self.break_states.pop())
                continues = self.continue_states.pop()
            for state in continues:  # `continue` jumps back to the loop head
                out = join_env(out, state)
            if isinstance(stmt, ast.While) and out is not None:
                self._scan(stmt.test, out)  # condition re-evaluated each iteration
            merged = join_env(current, out)
            if merged == current:
                break
            current = merged or current
        else:  # no fixpoint within the budget: give up precision, stay sound
            current = {k: combine((v, UNKNOWN)) for k, v in current.items()}
        # Normal exit (condition false / iterator exhausted) runs `else`; `break` skips it.
        normal_exit = join_env(entry, current)
        out_env = self.exec_block(stmt.orelse, normal_exit)  # type: ignore[attr-defined]
        for state in breaks:
            out_env = join_env(out_env, state)
        return out_env

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
        if self.try_states and final is not None:
            # An exception propagating out of this try carries the post-`finally` state
            # to the enclosing handler.
            self.try_states[-1].append(dict(final))
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
            base = _root_name(target)
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
        if isinstance(node, COMPREHENSION_TYPES):
            # Only the first iterable runs exactly once, now; the rest runs per item.
            generators = node.generators  # type: ignore[attr-defined]
            for gen in generators:  # `cmd.append(x) for cmd in commands` mutates commands
                for target in ast.walk(gen.target):
                    if isinstance(target, ast.Name):
                        for name in self._mutable_names_in(gen.iter, env):
                            self._union(target.id, name)
            self._scan(generators[0].iter, env)
            if self._mutates_targets(node):
                # An item is mutated in place: the containers it came from change too.
                for gen in generators:
                    for name in self._mutable_names_in(gen.iter, env):
                        self._weak_update(name, UNKNOWN, env)
            for gen in generators:  # `for d[k] in items` stores into d
                for target in ast.walk(gen.target):
                    if isinstance(target, (ast.Subscript, ast.Attribute)):
                        base = _root_name(target)
                        if base is not None:
                            self._weak_update(
                                base, combine((self.eval(gen.iter, env), UNKNOWN)), env
                            )
            rest = [generators[0].target, *generators[0].ifs]
            for gen in generators[1:]:
                rest += [gen.iter, gen.target, *gen.ifs]
            if isinstance(node, ast.DictComp):
                rest += [node.key, node.value]
            else:
                rest.append(node.elt)  # type: ignore[attr-defined]
            if isinstance(node, ast.GeneratorExp):
                # Runs when consumed, possibly after its free names were rebound, so
                # sinks there are never suppressed.
                self.deferred += 1
                try:
                    for part in rest:
                        self._scan(part, env)
                finally:
                    self.deferred -= 1
                return
            # Eager: filters run before the element, and each item sees the mutations of
            # the previous ones; scan to a fixpoint (sink values join over all visits).
            for _ in range(MAX_LOOP_ITERATIONS):
                before = dict(env)
                for part in rest:
                    self._scan(part, env)
                if env == before:
                    break
            else:  # no fixpoint within the budget: stay sound
                for key in list(env):
                    env[key] = combine((env[key], UNKNOWN))
                for part in rest:
                    self._scan(part, env)
            return
        callee = node.func if isinstance(node, ast.Call) else None
        for child in ast.iter_child_nodes(node):
            if child is callee and isinstance(child, ast.Attribute):
                self._scan(child.value, env)  # a method called right away, not extracted
            else:
                self._scan(child, env)
        if isinstance(node, ast.NamedExpr):
            self._assign(node.target, self.eval(node.value, env), env, node.value)
        elif isinstance(node, ast.Call):
            match = self.file.targets.get(id(node))
            if match is not None and match.arg is not None:
                value = self.eval(match.arg, env)
                if self.has_walrus or self.deferred:
                    value = combine((value, UNKNOWN))  # never suppressed (see __init__)
                self.file.record(node, value)
            if self.file.call_target(node) is not None:
                self._record_site(node, env)
            self._call_effects(node, env)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.ctx, ast.Load)
            and node.attr not in READONLY_METHODS | STRING_METHODS
        ):
            # `append = parts.append`: a bound method taken off a mutable object can
            # change it later from anywhere.
            for name in self._mutable_names_in(node.value, env):
                self._weak_update(name, UNKNOWN, env)

    def _mutates_targets(self, comp: ast.AST) -> bool:
        """Whether a comprehension may change one of its items in place: a target used
        as a non-read-only method receiver, stored into, or passed to a call that may
        keep or change it (sinks, sanitizers, pure builtins and string methods do not)."""
        targets = {
            t.id
            for gen in comp.generators  # type: ignore[attr-defined]
            for t in ast.walk(gen.target)
            if isinstance(t, ast.Name)
        }
        for node in ast.walk(comp):
            if isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr not in READONLY_METHODS | STRING_METHODS
                    and any(  # `[cmd][0].append(x)`, `(cmd if c else d).append(x)`
                        isinstance(n, ast.Name) and n.id in targets for n in ast.walk(func.value)
                    )
                ):
                    return True
                if any(
                    isinstance(n, ast.Name) and n.id in targets
                    for a in _call_args(node)
                    for n in ast.walk(a)  # also `change([cmd])`
                ) and not (
                    id(node) in self.file.targets
                    or self.ctx.call_names(node) & (NON_ESCAPING_CALLS | SANITIZERS.keys())
                    or (isinstance(func, ast.Attribute) and func.attr in STRING_METHODS)
                ):
                    return True
            if (
                isinstance(node, (ast.Subscript, ast.Attribute))
                and isinstance(node.ctx, ast.Store)
                and _root_name(node) in targets
            ):
                return True
        return False

    def _record_site(self, call: ast.Call, env: Env) -> None:
        positional = []
        for arg in call.args:
            if isinstance(arg, ast.Starred):
                break  # later positions are unknown
            positional.append(self.eval(arg, env))
        keywords = {k.arg: self.eval(k.value, env) for k in call.keywords if k.arg is not None}
        self.file.record_site(call, positional, keywords)

    def _call_effects(self, call: ast.Call, env: Env) -> None:
        args = _call_args(call)
        func = call.func
        # Mutating method on a mutable receiver: `parts.append(x)`, `d.setdefault(k, x)`.
        if isinstance(func, ast.Attribute) and func.attr not in READONLY_METHODS:
            # The receiver may be any object named in it: `d.get(k).append(x)` mutates d,
            # `(a if c else b).append(x)` mutates a or b.
            receivers = set(self._mutable_names_in(func.value, env))
            base = _root_name(func.value)
            if base is not None and self._lookup(base, func.value, env).mutable:
                receivers.add(base)
            if receivers:
                value = combine(self.eval(a, env) for a in args)
                for name in sorted(receivers):
                    self._weak_update(name, value, env)
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
            if isinstance(node, ast.GeneratorExp):
                # Produced when consumed, possibly after its free names were rebound.
                return combine((value, UNKNOWN))
            return replace(value, mutable=True)
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
        # A comprehension target shadows any outer binding of the same name.
        comp = self._comprehension_binding(name, node, env)
        if comp is not None:
            return comp
        # Class-body names are invisible inside comprehensions in that body.
        hidden = self.class_body and self.ctx.scopes.scope_of(node).node is not self.scope
        if name in env and not hidden:
            value = env[name]
            if (
                name in self.closure_stores
                or name in self.shared  # `global`/`nonlocal`: any call may rebind it
                or (name in self.closure_loads and value.mutable)
            ):
                return combine((value, UNKNOWN))  # another scope may change it
            return value
        for qualified in self.ctx.scopes.resolve_name(name, node):
            if qualified in SOURCE_NAMES:
                return source(SOURCE_NAMES[qualified], node)
        if (
            not self.is_module
            and name in self.file.module_constants
            and self.file.module_owned(name, node)  # not an enclosing function's local
        ):
            return CONST
        return UNKNOWN

    def _comprehension_binding(self, name: str, node: ast.AST, env: Env) -> Taint | None:
        scope = self.ctx.scopes.scope_of(node)
        while scope is not None and scope.is_comprehension:
            if name in scope.bindings:
                binders = [
                    gen
                    for gen in scope.node.generators  # type: ignore[attr-defined]
                    if any(isinstance(t, ast.Name) and t.id == name for t in ast.walk(gen.target))
                ]
                if len(binders) == 1 and not self._mutates_targets(scope.node):
                    return self.eval(binders[0].iter, env)
                return UNKNOWN  # rebound by a later `for`: which one applies depends on order
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
        value = self._call_value(node, env)
        if self.file.call_target(node) is None:
            return value
        if self.ctx.call_names(node) & (SOURCE_NAMES.keys() | SANITIZERS.keys()):
            return value
        # A linkable callee may return untrusted data of its own (resolved by `interproc`).
        return _with_symbol(value, ("ret", self.ctx.path, node.lineno, node.col_offset))

    def _call_value(self, node: ast.Call, env: Env) -> Taint:
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
                symbols=frozenset((a, s | safe) for a, s in value.symbols),
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


def _root_name(node: ast.AST) -> str | None:
    """Name a target or receiver is rooted at, also through method calls: `d.get(k)` or
    `d.setdefault(k, [])` may return an object stored in `d`, so changing it changes `d`."""
    while True:
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            node = node.func.value
        else:
            return node.id if isinstance(node, ast.Name) else None


def _closure_names(scope: ast.AST) -> tuple[frozenset[str], frozenset[str]]:
    """Names nested scopes inside `scope` read, and names they rebind (nonlocal/global)."""
    loads: set[str] = set()
    stores: set[str] = set()
    # Each outermost nested scope is walked once; its walk covers deeper nesting too.
    outermost: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            outermost.append(node)
        else:
            stack.extend(ast.iter_child_nodes(node))
    for node in outermost:
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name):
                loads.add(inner.id)
            elif isinstance(inner, ast.Nonlocal) or (
                isinstance(inner, ast.Global) and isinstance(scope, ast.Module)
            ):
                stores.update(inner.names)
    return frozenset(loads), frozenset(stores)


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Nodes of code that runs in `scope`. Nested function and class bodies are other
    scopes; their name, decorators, defaults and bases (and comprehensions, whose `:=`
    binds here) belong to this one."""
    if isinstance(scope, ast.Lambda):
        stack: list[ast.AST] = [scope.body]
    else:
        stack = list(scope.body)  # type: ignore[attr-defined]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            stack.extend(outer_parts(node))
            continue
        stack.extend(ast.iter_child_nodes(node))


def _has_own_walrus(scope: ast.AST) -> bool:
    return any(isinstance(node, ast.NamedExpr) for node in _own_nodes(scope))


def _declared_shared(scope: ast.AST) -> frozenset[str]:
    """Names `scope` declares `global`/`nonlocal` (other code may rebind them)."""
    if isinstance(scope, ast.Module):
        return frozenset()
    return frozenset(
        name
        for node in _own_nodes(scope)
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    )


def _module_binding_counts(tree: ast.Module) -> dict[str, int]:
    """How many binding sites each module-level name has (over-counting is safe)."""
    counts: dict[str, int] = {}
    for node in _own_nodes(tree):
        names: list[str] = []
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names = [node.id]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names = [node.name]
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [(a.asname or a.name).split(".")[0] for a in node.names]
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names = [node.name]
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names = [node.rest]
        for name in names:
            counts[name] = counts.get(name, 0) + 1
    return counts


# Ways code can write module globals by name at runtime.
NAMESPACE_FUNCTIONS = frozenset({"globals", "vars", "locals", "exec", "eval", "__import__"})
NAMESPACE_ATTRIBUTES = frozenset({"__dict__", "__globals__", "modules", "__builtins__"})


class _Namespace:
    """Whether a namespace may be written by name at runtime: the module's (anywhere in
    the file) or a class body's (only code in that body can). Any spelling counts:
    `exec`, `builtins.exec`, `from builtins import exec as run`, `run = exec` (assigned
    aliases are followed file-wide). Computed once per file."""

    def __init__(self, tree: ast.Module) -> None:
        self.imported = any(  # writers imported under another name
            (
                isinstance(node, ast.ImportFrom)
                and any(
                    a.name == "*"  # a star import may also rebind our names
                    or a.name in NAMESPACE_FUNCTIONS
                    or a.name in NAMESPACE_ATTRIBUTES
                    or a.name == "__builtins__"
                    for a in node.names
                )
            )
            or (
                isinstance(node, ast.Import)
                and any(a.name.split(".")[0] == "builtins" for a in node.names)
            )
            for node in ast.walk(tree)
        )
        self.writers = set(NAMESPACE_FUNCTIONS) | {"__builtins__"}
        self.module = self.imported or any(
            _mentions_writer(node, self.writers) for node in ast.walk(tree)
        )
        if not self.module:
            return  # no writer anywhere: no aliases either
        # Names bound (anywhere) from an expression that mentions a writer are writers too.
        assignments = [
            (node.value, node.targets if isinstance(node, ast.Assign) else [node.target])
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and node.value is not None
        ]
        changed = True
        while changed:
            changed = False
            for value, targets in assignments:
                if not any(_mentions_writer(part, self.writers) for part in ast.walk(value)):
                    continue
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and name.id not in self.writers:
                            self.writers.add(name.id)
                            changed = True

    def class_body(self, scope: ast.ClassDef) -> bool:
        if not self.module:
            return False
        return self.imported or any(
            _mentions_writer(node, self.writers) for node in _own_nodes(scope)
        )


def _mentions_writer(node: ast.AST, writers: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in writers
    if isinstance(node, ast.Attribute):
        return node.attr in NAMESPACE_ATTRIBUTES or node.attr in NAMESPACE_FUNCTIONS
    return False


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
