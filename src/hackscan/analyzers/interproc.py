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
suppresses a finding, because callers outside the scanned code are unknown. Resolution
is deliberately narrow (undecorated module-level functions, a name bound exactly once,
no star imports); anything else is simply not linked.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace

from hackscan.core.models import Evidence, Finding, Status
from hackscan.plugins.scopes import FUNCTION_TYPES

PRODUCER = "taint"
MAX_FIXPOINT_ROUNDS = 50
MAX_RESOLVE_DEPTH = 8
MAX_TRACE_STEPS = 5
CONFIRMED_CONFIDENCE_BOOST = 35

# ("param", path, function, parameter) | ("ret", path, line, column)
Atom = tuple
# An atom with the vulnerability classes its value has been sanitized for on the way.
SymbolPair = tuple[Atom, frozenset[str]]
# (path, line, description) of an untrusted source.
SourceRef = tuple[str, int, str]
Reached = frozenset[tuple[SourceRef, frozenset[str]]]


@dataclass(frozen=True)
class Flow:
    """A value: concrete sources (all sanitized for `safe`) plus symbolic parts."""

    sources: frozenset[SourceRef] = frozenset()
    safe: frozenset[str] = frozenset()
    symbols: frozenset[SymbolPair] = frozenset()

    def __bool__(self) -> bool:
        return bool(self.sources or self.symbols)


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


@dataclass
class FileFacts:
    path: str
    module: str
    symbols: dict[str, tuple[str, str]] = field(default_factory=dict)  # name -> (kind, target)
    functions: dict[str, FunctionFacts] = field(default_factory=dict)
    sites: dict[tuple[int, int], CallSite] = field(default_factory=dict)
    sinks: dict[tuple, Flow] = field(default_factory=dict)  # finding_key -> value


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

    def resolve(self, dotted: str, depth: int = 0) -> tuple[str, str] | None:
        """(path, function) a dotted name denotes, following imports and re-exports."""
        if depth > MAX_RESOLVE_DEPTH:
            return None
        parts = dotted.split(".")
        for i in range(len(parts) - 1, 0, -1):
            facts = self._module(".".join(parts[:i]))
            if facts is None:
                continue
            rest = parts[i:]
            entry = facts.symbols.get(rest[0])
            if entry is None:
                return None
            kind, target = entry
            if kind == "def":
                if len(rest) == 1 and rest[0] in facts.functions:
                    return facts.path, rest[0]
                return None
            return self.resolve(".".join([target, *rest[1:]]), depth + 1)
        return None


def _bind_arguments(site: CallSite, func: FunctionFacts) -> list[tuple[str, Flow]]:
    bound = list(zip(func.positional, site.positional, strict=False))
    bound += [(name, flow) for name, flow in site.keywords if name in func.keyword]
    return bound


def _reach(flow: Flow, values: dict[Atom, set], skip: frozenset = frozenset()) -> set:
    out = {(s, flow.safe) for s in flow.sources}
    for atom, safe in flow.symbols:
        if atom in skip:
            continue
        for source, inner in values.get(atom, ()):
            out.add((source, inner | safe))
    return out


def solve(facts: list[FileFacts]) -> tuple[dict[Atom, set], dict[tuple, tuple[str, str]]]:
    """Least fixpoint of the sources reaching every parameter and call result."""
    program = _Program(facts)
    callees: dict[tuple, tuple[str, str]] = {}  # (path, line, col) -> (path, function)
    equations: list[tuple[Atom, Flow, frozenset]] = []
    for f in sorted(facts, key=lambda x: x.path):
        for (line, col), site in sorted(f.sites.items()):
            target = program.resolve(site.target)
            if target is None:
                continue
            callees[(f.path, line, col)] = target
            callee = program.files[target[0]].functions[target[1]]
            for name, flow in _bind_arguments(site, callee):
                equations.append((("param", *target, name), flow, frozenset()))
            if callee.returns:
                # Arguments already flow through any call; only sources inside the callee
                # (and further calls) are new, so the callee's own parameters are skipped.
                own = frozenset(
                    ("param", *target, p) for p in callee.keyword | set(callee.positional)
                )
                equations.append((("ret", f.path, line, col), callee.returns, own))
    values: dict[Atom, set] = {}
    for _ in range(MAX_FIXPOINT_ROUNDS):
        changed = False
        for atom, flow, skip in equations:
            reached = _reach(flow, values, skip)
            current = values.setdefault(atom, set())
            if not reached <= current:
                current |= reached
                changed = True
        if not changed:
            break
    return values, callees


def confirm_findings(findings: list[Finding], facts: list[FileFacts]) -> list[Finding]:
    """Confirm candidates whose value reaches an untrusted source through calls."""
    by_path = {f.path: f for f in facts}
    if not any(f.sinks for f in facts):
        return findings
    values, _ = solve(facts)
    out = []
    for finding in findings:
        file = by_path.get(finding.location.path)
        flow = file.sinks.get(finding_key(finding)) if file else None
        if flow is None or finding.status is not Status.CANDIDATE:
            out.append(finding)
            continue
        steps = _trace(finding, flow, values, file)
        out.append(_confirm(finding, steps) if steps else finding)
    return out


def _trace(finding: Finding, flow: Flow, values: dict[Atom, set], file: FileFacts) -> list[str]:
    steps: set[str] = set()
    for atom, safe in flow.symbols:
        label = _label(atom, file)
        for (path, line, description), inner in values.get(atom, ()):
            if finding.vuln_class not in (inner | safe):
                steps.add(f"Untrusted {description} at {path}:{line} reaches {label}.")
    return sorted(steps)[:MAX_TRACE_STEPS]


def _label(atom: Atom, file: FileFacts) -> str:
    if atom[0] == "param":
        return f"parameter `{atom[3]}` of `{atom[2]}`"
    site = file.sites.get((atom[2], atom[3]))
    target = site.target if site else "a function"
    return f"the value returned by `{target}` (line {atom[2]})"


def _confirm(finding: Finding, steps: list[str]) -> Finding:
    kept = tuple(
        e for e in finding.evidence if not (e.producer == PRODUCER and e.kind == "taint_verdict")
    )
    return replace(
        finding,
        status=Status.CONFIRMED,
        confidence=min(100, finding.confidence + CONFIRMED_CONFIDENCE_BOOST),
        evidence=(
            *kept,
            *(Evidence(PRODUCER, "taint_step", s) for s in steps),
            Evidence(PRODUCER, "taint_verdict", "Untrusted input reaches the sink through calls."),
        ),
    )
