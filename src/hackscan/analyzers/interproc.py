"""Inter-procedural, cross-file taint (confirmation only).

Pass 2 (`taint_pass`) analyzes one function at a time. A parameter's value is unknown
there, so a sink fed by a parameter stays a candidate. While analyzing, each file also
records *symbolic* facts:

- the parameters (and calls) a candidate sink's value depends on,
- what each module-level function returns,
- the argument values at every call whose target can be named statically.

`confirm_findings` then links the facts of all files: calls are resolved to module-level
functions (same module, `import`/`from ... import`, relative imports and re-exports) and
a least fixpoint computes which untrusted sources can reach each parameter and return
value. A candidate whose value may come from such a source becomes confirmed.

Soundness stance: this pass only *adds* sources (candidate -> confirmed). It never
suppresses a finding, because callers outside the scanned code are unknown.

Certainty: a value that passes through a call nobody models (an unresolved function, an
unmodelled method) may still carry untrusted data, but that flow is *assumed*, not
established. Such parts carry the `ASSUMED` marker in their sanitized-for set (it survives
every join and link), and only a flow without it confirms a finding. A call to a linked
function establishes its result per call site: the callee's returned parameters are
replaced by that site's arguments. Resolution
is deliberately narrow (undecorated module-level functions, a name bound exactly once,
no star imports); anything else is simply not linked.
"""

from __future__ import annotations

import ast
import functools
from dataclasses import dataclass, field, replace

from hackscan.core.models import ASSUMED_VERDICT, CONFIRMED_VERDICT, Evidence, Finding, Status
from hackscan.plugins.scopes import FUNCTION_TYPES

PRODUCER = "taint"
MAX_FIXPOINT_ROUNDS = 50
MAX_RESOLVE_DEPTH = 8
MAX_TRACE_STEPS = 5
CONFIRMED_CONFIDENCE_BOOST = 35
# Marks a symbolic part or a reached source whose flow went through an unmodelled call:
# `ASSUMED` + ":" + the call (which, and where), kept in its sanitized-for set.
ASSUMED = "~assumed"


def is_assumed(marks: frozenset[str]) -> bool:
    return any(m.startswith(ASSUMED) for m in marks)


def assumed_calls(marks: frozenset[str]) -> list[str]:
    return sorted(m[len(ASSUMED) + 1 :] for m in marks if m.startswith(ASSUMED + ":"))


# Shell-quoting credit for a class (context-sensitive: lost when the quoting may break),
# kept apart from plain credit (a number stays a number).
QUOTED = "~quoted"
# Marks a symbolic part whose earlier credit was invalidated on the way (`n.to_bytes()`):
# `DROP` + the class (or quoting mark). It applies to credit given before it, by a caller.
DROP = "~drop:"


# Credit that holds because the value is a number's text (`str(int(x))`): kept apart, as
# transformations that cannot make other characters out of digits keep it.
DIGITS = "~digits"


# Marks a path that is established only through a library model (`json.loads`): `MODEL` +
# the model's name. Where scanned code may replace that model, the path is assumed instead.
MODEL = "~model:"
# Library modules under another name.
MODULE_ALIASES = {"posixpath": "os.path", "ntpath": "os.path"}


def models_of(marks: frozenset[str]) -> frozenset[str]:
    """The library functions a path depends on (without where the call binds them)."""
    return frozenset(m[len(MODEL) :].split("@")[0] for m in marks if m.startswith(MODEL))


def quoted(cls: str) -> str:
    return cls + QUOTED


def digits(cls: str) -> str:
    return cls + DIGITS


def sanitized_for(marks: frozenset[str], cls: str) -> bool:
    return cls in marks or quoted(cls) in marks or digits(cls) in marks


@functools.lru_cache(maxsize=1 << 16)
def then(earlier: frozenset[str], later: frozenset[str]) -> frozenset[str]:
    """The marks of a path that went through `earlier`, then `later`: credit `later`
    invalidated is gone, and both its drops stay (they also apply to anything before)."""
    drops = {m[len(DROP) :] for m in later if m.startswith(DROP)}
    return join_marks(earlier - drops if drops else earlier, later)


@functools.lru_cache(maxsize=1 << 16)  # called for every pair on every link
def join_marks(*parts: frozenset[str]) -> frozenset[str]:
    """The union of marks along a path, keeping one unmodelled call (the first by name) as
    the example: whether a path is assumed is exact, but recording every combination of the
    calls on it would multiply the pairs a value holds."""
    marks = frozenset().union(*parts)
    calls = [m for m in marks if m.startswith(ASSUMED)]
    return marks if len(calls) <= 1 else (marks - set(calls)) | {min(calls)}


# ("param", path, function, parameter) | ("ret", path, line, column)
Atom = tuple
# An atom with the vulnerability classes its value has been sanitized for on the way.
SymbolPair = tuple[Atom, frozenset[str]]
# (path, line, description) of an untrusted source.
SourceRef = tuple[str, int, str]
Reached = frozenset[tuple[SourceRef, frozenset[str]]]


@dataclass(frozen=True)
class Flow:
    """A value: concrete sources (each with what it was sanitized for on its way) plus
    symbolic parts; `safe` is what the whole value is sanitized for."""

    sources: frozenset[tuple[SourceRef, frozenset[str]]] = frozenset()
    safe: frozenset[str] = frozenset()
    symbols: frozenset[SymbolPair] = frozenset()
    # reached only through unmodelled calls (their marks name the calls)
    assumed_sources: frozenset[tuple[SourceRef, frozenset[str]]] = frozenset()

    def __bool__(self) -> bool:
        return bool(self.sources or self.symbols or self.assumed_sources)


@dataclass(frozen=True)
class FunctionFacts:
    positional: tuple[str, ...]  # positional-only + positional-or-keyword parameters
    keyword: frozenset[str]  # parameters that may be passed by keyword
    returns: Flow | None


@dataclass(frozen=True)
class CallSite:
    target: str  # absolute dotted name of the callee (e.g. `app.utils.run`)
    line: int
    positional: tuple[Flow, ...]  # stops at the first `*args`
    keywords: tuple[tuple[str, Flow], ...]
    root: str = ""  # the name the caller reaches the callee through (`go` of `go(x)`)


@dataclass
class FileFacts:
    path: str
    module: str
    symbols: dict[str, tuple[str, str]] = field(default_factory=dict)  # name -> (kind, target)
    functions: dict[str, FunctionFacts] = field(default_factory=dict)
    sites: dict[tuple[int, int], CallSite] = field(default_factory=dict)
    sinks: dict[tuple, Flow] = field(default_factory=dict)  # finding_key -> value
    # (entry, line): function names this file may replace in any module
    # (`helpers.ident = ...`, `setattr` with that name, `helpers.__dict__['ident'] = ...`),
    # and "module:<dotted>" for any name of an imported module.
    replaced: frozenset[tuple[str, int]] = frozenset()


def finding_key(finding: Finding) -> tuple:
    loc = finding.location
    return (
        finding.rule_id,
        loc.start_line,
        loc.start_column,
        loc.end_line,
        loc.end_column,
    )


# -- per-file helpers (used by taint_pass) -------------------------------------------------


def module_name(rel_path: str) -> str:
    """Dotted module name of a path relative to the scan root."""
    parts = rel_path.split("/")
    parts[-1] = parts[-1].rsplit(".", 1)[0]
    if parts[-1] == "__init__" and len(parts) > 1:
        parts.pop()
    return ".".join(parts)


def _package(rel_path: str, module: str) -> list[str]:
    parts = module.split(".")
    return parts if rel_path.endswith("/__init__.py") or rel_path == "__init__.py" else parts[:-1]


def module_symbols(tree: ast.Module, rel_path: str) -> dict[str, tuple[str, str]]:
    """Module-level names bound exactly once, to an undecorated function or an import.

    Value: ("def", name) or ("import", absolute dotted target). Names declared `global`
    anywhere, bound more than once, or in a module with a star import are left out: the
    callee would not be certain.
    """
    counts: dict[str, int] = {}
    kinds: dict[str, tuple[str, str] | None] = {}
    rebound: set[str] = set()
    module = module_name(rel_path)

    def bind(name: str, value: tuple[str, str] | None) -> None:
        counts[name] = counts.get(name, 0) + 1
        kinds[name] = value

    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Global):
            rebound.update(node.names)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            plain = not node.decorator_list and not _is_generator(node)
            bind(node.name, ("def", node.name) if plain and node in tree.body else None)
            stack.extend(_nested_globals(node))
            stack.extend(outer_parts(node))
            continue
        if isinstance(node, ast.ClassDef):
            bind(node.name, None)
            stack.extend(_nested_globals(node))
            stack.extend(outer_parts(node))
            continue
        if isinstance(node, ast.Lambda):
            stack.extend(outer_parts(node))
            continue
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            return {}
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    bind(a.asname, ("import", a.name))
                else:
                    top = a.name.split(".")[0]
                    bind(top, ("import", top))
        elif isinstance(node, ast.ImportFrom):
            base = _import_base(node, rel_path, module)
            for a in node.names:
                target = f"{base}.{a.name}" if base else None
                bind(a.asname or a.name, ("import", target) if target else None)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bind(node.id, None)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            bind(node.name, None)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bind(node.rest, None)
        stack.extend(ast.iter_child_nodes(node))
    return {
        name: value
        for name, value in kinds.items()
        if value is not None and counts[name] == 1 and name not in rebound
    }


def _import_base(node: ast.ImportFrom, rel_path: str, module: str) -> str | None:
    if node.level == 0:
        return node.module
    package = _package(rel_path, module)
    if node.level - 1 > len(package):
        return None
    base = package[: len(package) - (node.level - 1)]
    if node.module:
        base = [*base, *node.module.split(".")]
    return ".".join(base) or None


def outer_parts(node: ast.AST) -> list[ast.AST]:
    """Parts of a def/class/lambda evaluated in the enclosing scope (may bind via `:=`)."""
    parts: list[ast.AST] = list(getattr(node, "decorator_list", []))
    if isinstance(node, ast.ClassDef):
        return [*parts, *node.bases, *(k.value for k in node.keywords)]
    args = node.args  # type: ignore[attr-defined]
    parts += [*args.defaults, *(d for d in args.kw_defaults if d is not None)]
    if not isinstance(node, ast.Lambda):
        every = (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
        parts += [a.annotation for a in every if a is not None and a.annotation is not None]
        if node.returns is not None:  # type: ignore[attr-defined]
            parts.append(node.returns)  # type: ignore[attr-defined]
    return parts


def _nested_globals(node: ast.AST) -> list[ast.AST]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Global)]


def _is_generator(func: ast.AST) -> bool:
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if not isinstance(node, (*FUNCTION_TYPES, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))
    return False


def linkable_functions(tree: ast.Module, symbols: dict[str, tuple[str, str]]) -> list[ast.AST]:
    """Module-level functions other files (and this one) can be linked to."""
    return [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and symbols.get(node.name) == ("def", node.name)
    ]


def parameters(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[tuple[str, ...], frozenset]:
    args = func.args
    positional = tuple(a.arg for a in (*args.posonlyargs, *args.args))
    keyword = frozenset(a.arg for a in (*args.args, *args.kwonlyargs))
    return positional, keyword


# -- linking ------------------------------------------------------------------------------


class _Program:
    def __init__(self, facts: list[FileFacts]) -> None:
        self.files = {f.path: f for f in facts}
        self.by_module: dict[str, list[FileFacts]] = {}
        for f in facts:
            self.by_module.setdefault(f.module, []).append(f)

    def _module(self, dotted: str) -> FileFacts | None:
        exact = self.by_module.get(dotted)
        if exact:
            return exact[0] if len(exact) == 1 else None
        # `app.utils` may live at `src/app/utils.py` (the scan root is above sys.path).
        matches = [
            f
            for name, files in self.by_module.items()
            if name.endswith("." + dotted)
            for f in files
        ]
        return matches[0] if len(matches) == 1 else None

    def resolve(
        self, dotted: str, depth: int = 0, hops: list[tuple[str, str]] | None = None
    ) -> tuple[str, str] | None:
        """(path, function) a dotted name denotes, following imports and re-exports. Each
        (path, name) on the way is added to `hops` (a re-export can be replaced too)."""
        if depth > MAX_RESOLVE_DEPTH:
            return None
        parts = dotted.split(".")
        if hops is not None:  # `pkg.helpers.ident`: `pkg.helpers = ...` replaces it too
            hops.extend(("", part) for part in parts[:-1])
            for k in range(1, len(parts)):  # and so does any parent module that may be replaced
                parent = self._module(".".join(parts[:k]))
                if parent is not None:
                    hops.append((parent.path, parts[k]))
        for i in range(len(parts) - 1, 0, -1):
            facts = self._module(".".join(parts[:i]))
            if facts is None:
                continue
            rest = parts[i:]
            if hops is not None:
                hops.append((facts.path, rest[0]))
            entry = facts.symbols.get(rest[0])
            if entry is None:
                return None
            kind, target = entry
            if kind == "def":
                if len(rest) == 1 and rest[0] in facts.functions:
                    return facts.path, rest[0]
                return None
            return self.resolve(".".join([target, *rest[1:]]), depth + 1, hops)
        return None


class _Replacements:
    """What scanned code may replace at runtime, and where: names (in any module), scanned
    files (every name, `module:` matched like an import) and library modules."""

    def __init__(self, program: _Program, facts: list[FileFacts]) -> None:
        self.program = program
        self.names: dict[str, str] = {}
        self.paths: dict[str, str] = {}
        self.modules: dict[str, str] = {}
        self._resolved: dict[frozenset[str], frozenset[str]] = {}
        self._shadows: dict[str, str | None] = {}
        self.path_attrs: dict[tuple[str, str], str] = {}  # (scanned file, name) set from outside
        self.everything: str | None = None  # `module:*`: any module may be replaced
        for f in sorted(facts, key=lambda x: x.path):
            for entry, line in sorted(f.replaced):
                where = f"{f.path}:{line}"
                if entry.startswith("globals:"):
                    # `fn.__globals__` written: the namespace of the module defining `fn`
                    dotted = entry[len("globals:") :]
                    target = program.resolve(dotted)
                    owner = dotted.rsplit(".", 1)[0]
                    if target is not None:
                        self.paths.setdefault(target[0], where)
                    elif program._module(owner) is not None:
                        self.everything = self.everything or where  # scanned, but not resolved
                    else:
                        self.modules.setdefault(MODULE_ALIASES.get(owner, owner), where)
                    continue
                if entry.startswith("attr:"):
                    # `app.json = ...`: a name in a module's namespace, set from outside
                    dotted, _, name = entry[len("attr:") :].rpartition(".")
                    module = program._module(dotted)
                    if module is not None:
                        self.path_attrs.setdefault((module.path, name), where)
                    continue
                if not entry.startswith("module:"):
                    self.names.setdefault(entry, where)
                    continue
                dotted = entry[len("module:") :]
                if dotted == "*":
                    self.everything = self.everything or where
                    continue
                module = program._module(dotted)
                if module is not None:
                    self.paths.setdefault(module.path, where)
                # (a scanned namesake inside a package may not be what is meant: the library
                # module of that name is recorded too)
                self.modules.setdefault(MODULE_ALIASES.get(dotted, dotted), where)

    def hop(self, path: str, name: str) -> bool:
        return self.everything is not None or name in self.names or path in self.paths

    def model(self, model: str) -> str | None:
        """Where scanned code may replace the library function `model`, if anywhere.
        `model` may carry where it is called and the name it is reached through
        (`json.loads@app.py@json`): the caller's namespace written, or that name set in it
        from outside (`app.json = ...`), replaces it too."""
        if self.everything is not None:
            return self.everything
        model, _, site = model.partition("@")
        path, _, root = site.partition("@")
        if path and path in self.paths:
            return self.paths[path]
        if path and (path, root) in self.path_attrs:
            return self.path_attrs[(path, root)]
        parts = model.split(".")
        owner = ".".join(parts[:-1]) or "builtins"
        shadow = self.shadowed(owner)
        if shadow is not None:
            return shadow  # a scanned module of that name is imported instead of the library
        for part in parts[1:] or parts:  # the function, and a submodule on the way (os.path)
            if part in self.names:
                return self.names[part]
        for module, where in sorted(self.modules.items()):
            if owner == module or owner.startswith(module + "."):
                return where
        return None

    def shadowed(self, module: str) -> str | None:
        """The scanned file imported as library `module` (`json.py` at a source root), if
        any: its own code runs, not the library the model describes."""
        if module == "builtins":
            return None  # always the interpreter's own
        parent = module.rpartition(".")[0]
        if parent:  # `urllib.py` supplies `urllib.parse` too
            found = self.shadowed(parent)
            if found is not None:
                return found
        if module not in self._shadows:
            found = None
            for f in sorted(self.program.files.values(), key=lambda x: x.path):
                if f.module != module and not f.module.endswith("." + module):
                    continue
                depth = len(module.split(".")) + (1 if f.path.endswith("__init__.py") else 0)
                root = "/".join(f.path.split("/")[:-depth])
                if not root or f"{root}/__init__.py" not in self.program.files:
                    found = f"{f.path}:1"  # a module at a source root, not inside a package
                    break
            self._shadows[module] = found
        return self._shadows[module]

    def resolve_marks(self, marks: frozenset[str]) -> frozenset[str]:
        """`marks` with its model dependencies decided: a model nothing scanned replaces is
        modelled (its mark goes); one that scanned code may replace makes the path assumed."""
        models = [m for m in marks if m.startswith(MODEL)]
        if not models:
            return marks
        key = marks
        if key not in self._resolved:
            out = marks - set(models)
            for mark in sorted(models):
                name = mark[len(MODEL) :]
                where = self.model(name)
                if where is not None:
                    shown = name.split("@")[0]  # (without where the call binds it)
                    note = f"{ASSUMED}:`{shown}`, which scanned code may replace ({where})"
                    out = join_marks(out, frozenset({note}))
            self._resolved[key] = out
        return self._resolved[key]

    def flow(self, flow: Flow) -> Flow:
        def pairs(items):
            return frozenset((x, self.resolve_marks(m)) for x, m in items)

        return replace(
            flow,
            sources=pairs(flow.sources),
            symbols=pairs(flow.symbols),
            assumed_sources=pairs(flow.assumed_sources),
        )

    def facts(self, f: FileFacts) -> FileFacts:
        """`f` with every flow's model dependencies decided (see `resolve_marks`)."""
        return replace(
            f,
            functions={
                n: replace(fn, returns=self.flow(fn.returns) if fn.returns else fn.returns)
                for n, fn in f.functions.items()
            },
            sites={
                k: replace(
                    s,
                    positional=tuple(self.flow(a) for a in s.positional),
                    keywords=tuple((n, self.flow(a)) for n, a in s.keywords),
                )
                for k, s in f.sites.items()
            },
            sinks={k: self.flow(v) for k, v in f.sinks.items()},
        )


def _bind_arguments(site: CallSite, func: FunctionFacts) -> list[tuple[str, Flow]]:
    bound = list(zip(func.positional, site.positional, strict=False))
    bound += [(name, flow) for name, flow in site.keywords if name in func.keyword]
    return bound


def _reach(flow: Flow, values: dict[Atom, set]) -> set:
    """The (source, marks) pairs reaching `flow` in its own context: marks are the classes
    it was sanitized for on the way, and `ASSUMED` markers of unmodelled calls."""
    out = set(flow.sources) | set(flow.assumed_sources)
    for atom, safe in flow.symbols:
        for source, inner in values.get(atom, ()):
            out.add((source, then(inner, safe)))
    return out


# A function's return summary: what its result depends on, independent of the call site:
# ("src", source, marks) for untrusted data of its own, ("param", name, marks) for a parameter.
Summary = set


def _summarize(flow: Flow, key: tuple[str, str], ctx: _Linking) -> Summary:
    """The summary of `flow`, a value inside function `key`. A nested call's result is
    replaced by what that call site passes for the parameters its callee returns. Those
    arguments may depend on each other (`x = f(x)` in a loop), so their summaries are a
    least fixpoint: each is computed once per pass, from the others' current summaries."""
    nodes: dict[tuple, Flow] = {}
    pending = [flow]
    while pending:
        for arg, passed in _nested_arguments(pending.pop(), ctx):
            if arg not in nodes:
                nodes[arg] = passed
                pending.append(passed)
    memo: dict[tuple, Summary] = {arg: set() for arg in nodes}
    order = sorted(nodes)
    changed = True
    while changed:
        changed = False
        for arg in order:
            summary = _summary_step(nodes[arg], key, ctx, memo)
            if not summary <= memo[arg]:
                memo[arg] = memo[arg] | summary
                changed = True
    return _summary_step(flow, key, ctx, memo)


def _nested_arguments(flow: Flow, ctx: _Linking):
    """(site, parameter) and the argument passed there, for every linked call in `flow`
    whose callee returns that parameter."""
    for atom, _ in flow.symbols:
        if atom[0] == "ret" and atom[1:] in ctx.callees:
            site = atom[1:]
            for entry in ctx.summaries.get(ctx.callees[site], ()):
                if entry[0] == "param" and (passed := ctx.arguments[site].get(entry[1])):
                    yield (site, entry[1]), passed


def _summary_step(flow: Flow, key: tuple[str, str], ctx: _Linking, memo: dict) -> Summary:
    out: Summary = {("src", s, marks) for s, marks in (*flow.sources, *flow.assumed_sources)}
    for atom, safe in flow.symbols:
        if atom[0] == "param" and (atom[1], atom[2]) == key:
            out.add(("param", atom[3], safe))
        elif atom[0] == "ret" and atom[1:] in ctx.callees:
            site = atom[1:]
            for entry in ctx.summaries.get(ctx.callees[site], ()):
                if entry[0] == "src":
                    out.add(("src", entry[1], then(entry[2], safe)))
                    continue
                for kind, what, marks in memo.get((site, entry[1]), ()):
                    out.add((kind, what, then(then(marks, entry[2]), safe)))
        else:
            for source, inner in ctx.values.get(atom, ()):
                out.add(("src", source, then(inner, safe)))
    return out


def _instantiate(summary: Summary, arguments: dict[str, Flow], values: dict[Atom, set]) -> set:
    """A callee's result at one call site: its own data, and what this site passes for the
    parameters it returns (a parameter the site does not pass holds its default)."""
    out = set()
    for kind, what, marks in summary:
        if kind == "src":
            out.add((what, marks))
        elif (passed := arguments.get(what)) is not None:
            for source, inner in _reach(passed, values):
                out.add((source, then(inner, marks)))
    return out


@dataclass
class _Linking:
    callees: dict[tuple, tuple[str, str]]  # (path, line, col) -> (path, function)
    arguments: dict[tuple, dict[str, Flow]]  # (path, line, col) -> parameter -> flow passed
    summaries: dict[tuple[str, str], Summary] = field(default_factory=dict)
    values: dict[Atom, set] = field(default_factory=dict)


def solve(facts: list[FileFacts]) -> tuple[dict[Atom, set], dict[tuple, tuple[str, str]]]:
    """Least fixpoint of the sources reaching every parameter (from any call site) and every
    call result (per call site, through the callee's return summary)."""
    program = _Program(facts)
    replaced = _Replacements(program, facts)
    facts = [replaced.facts(f) for f in facts]
    return _solve(facts, _Program(facts), replaced)


def _solve(
    facts: list[FileFacts], program: _Program, replaced: _Replacements
) -> tuple[dict[Atom, set], dict[tuple, tuple[str, str]]]:
    ctx = _Linking({}, {})
    params: list[tuple[Atom, Flow]] = []
    for f in sorted(facts, key=lambda x: x.path):
        for (line, col), site in sorted(f.sites.items()):
            hops: list[tuple[str, str]] = []
            target = program.resolve(site.target, hops=hops)
            if target is None:
                continue
            if any(replaced.hop(path, name) for path, name in hops):
                continue  # the function, or a name on the way to it, may be replaced at runtime
            if f.path in replaced.paths or (f.path, site.root) in replaced.path_attrs:
                continue  # the caller's own binding may be replaced (`app.go = ...`)
            ctx.callees[(f.path, line, col)] = target
            bound = _bind_arguments(site, program.files[target[0]].functions[target[1]])
            ctx.arguments[(f.path, line, col)] = dict(bound)
            params += [(("param", *target, name), flow) for name, flow in bound]
    functions = [
        ((f.path, name), facts_.returns)
        for f in sorted(facts, key=lambda x: x.path)
        for name, facts_ in sorted(f.functions.items())
        if facts_.returns
    ]
    for _ in range(MAX_FIXPOINT_ROUNDS):
        changed = False
        for key, returns in functions:
            summary = _summarize(returns, key, ctx)
            current = ctx.summaries.setdefault(key, set())
            if not summary <= current:
                current |= summary
                changed = True
        for atom, flow in params:
            reached = _reach(flow, ctx.values)
            current = ctx.values.setdefault(atom, set())
            if not reached <= current:
                current |= reached
                changed = True
        for site, target in ctx.callees.items():
            reached = _instantiate(
                ctx.summaries.get(target, set()), ctx.arguments[site], ctx.values
            )
            current = ctx.values.setdefault(("ret", *site), set())
            if not reached <= current:
                current |= reached
                changed = True
        if not changed:
            break
    return ctx.values, ctx.callees


def confirm_findings(findings: list[Finding], facts: list[FileFacts]) -> list[Finding]:
    """Confirm candidates whose value reaches an untrusted source through calls."""
    by_path = {f.path: f for f in facts}
    if not any(f.sinks for f in facts):
        return findings
    program = _Program(facts)
    replaced = _Replacements(program, facts)
    # Model dependencies are decided once, before linking: the marks stay small.
    facts = [replaced.facts(f) for f in facts]
    by_path = {f.path: f for f in facts}
    program = _Program(facts)
    values, _ = _solve(facts, program, replaced)
    out = []
    for finding in findings:
        file = by_path.get(finding.location.path)
        flow = file.sinks.get(finding_key(finding)) if file else None
        if flow is None or finding.status is not Status.CANDIDATE:
            out.append(finding)
            continue
        steps = _trace(finding, flow, values, file, replaced)
        if steps:
            out.append(_confirm(finding, steps))
            continue
        assumed = _trace(finding, flow, values, file, replaced, assumed=True)
        out.append(_note_assumed(finding, assumed) if assumed else finding)
    return out


def _trace(
    finding: Finding,
    flow: Flow,
    values: dict[Atom, set],
    file: FileFacts,
    replaced: _Replacements,
    *,
    assumed: bool = False,
) -> list[str]:
    """Established (or, with `assumed`, assumed-only) unsanitized paths into the sink. (A path
    through a library model that scanned code may replace is assumed: `resolve_marks`.)"""
    steps: set[str] = set()
    for (_path, line, description), marks in flow.sources:  # here, maybe through models
        if sanitized_for(marks, finding.vuln_class) or is_assumed(marks) != assumed:
            continue
        if assumed:
            calls = ", ".join(assumed_calls(marks)) or "a call"
            steps.add(
                f"Untrusted {description} at line {line} may reach the sink, but only through "
                f"calls that are not modelled (such as {calls})."
            )
        else:
            steps.add(f"Modelled flow: untrusted {description} at line {line}.")
    for atom, safe in flow.symbols:
        label = _label(atom, file)
        for (path, line, description), inner in values.get(atom, ()):
            marks = then(inner, safe)
            if sanitized_for(marks, finding.vuln_class) or is_assumed(marks) != assumed:
                continue
            if assumed:
                calls = ", ".join(assumed_calls(marks)) or "a call"
                steps.add(
                    f"Untrusted {description} at {path}:{line} may reach {label}, but only "
                    f"through calls that are not modelled (such as {calls})."
                )
            else:
                steps.add(
                    f"Modelled flow: untrusted {description} at {path}:{line} reaches {label}."
                )
    return sorted(steps)[:MAX_TRACE_STEPS]


def _note_assumed(finding: Finding, steps: list[str]) -> Finding:
    """A candidate stays a candidate; the possible but unestablished paths are recorded, and
    its verdict is the contract's candidate verdict."""
    kept = tuple(
        e for e in finding.evidence if not (e.producer == PRODUCER and e.kind == "taint_verdict")
    )
    return replace(
        finding,
        evidence=(
            *kept,
            *(Evidence(PRODUCER, "taint_step", s) for s in steps),
            Evidence(PRODUCER, "taint_verdict", ASSUMED_VERDICT),
        ),
    )


def _label(atom: Atom, file: FileFacts) -> str:
    if atom[0] == "param":
        return f"parameter `{atom[3]}` of `{atom[2]}`"
    site = file.sites.get((atom[2], atom[3]))
    target = site.target if site else "a function"
    return f"the value returned by `{target}` (line {atom[2]})"


def _confirm(finding: Finding, steps: list[str]) -> Finding:
    # The established path replaces the verdict and the local "may reach" notes.
    kept = tuple(
        e
        for e in finding.evidence
        if not (
            e.producer == PRODUCER
            and (
                e.kind == "taint_verdict"
                or (e.kind == "taint_step" and "not modelled" in e.message)
            )
        )
    )
    return replace(
        finding,
        status=Status.CONFIRMED,
        confidence=min(100, finding.confidence + CONFIRMED_CONFIDENCE_BOOST),
        evidence=(
            *kept,
            *(Evidence(PRODUCER, "taint_step", s) for s in steps),
            Evidence(
                PRODUCER,
                "taint_verdict",
                CONFIRMED_VERDICT,
            ),
        ),
    )
