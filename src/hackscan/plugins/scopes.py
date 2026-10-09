"""Lexical scopes and name bindings, following Python's scoping rules closely enough
for sink resolution (and, from M2, taint tracking).

- Function bodies (def/async def/lambda) and comprehensions are scopes. Decorators,
  default values, annotations and a comprehension's first iterable are evaluated in the
  *enclosing* scope.
- Class bodies are scopes visible only to code directly in the class body (not to
  methods or comprehensions inside the class).
- `global` redirects a name to the module scope; `nonlocal` to the enclosing function.
  An assignment expression (`:=`) inside a comprehension binds in the enclosing scope.
- Bindings are flow-insensitive *may* sets: a scope records every way it binds a name.
  Resolution is recall-oriented: if the binding scope imports the name anywhere
  (`import os` ... `os = fallback`, try/except or conditional imports), the name may be
  that module and resolves to it. Only names bound exclusively by non-import bindings
  (parameters, assignments, loop targets) resolve to "local value" (empty set).
- Unbound names resolve to themselves (builtins) and, if a `from m import *` is in scope,
  also to `m.<name>`.
"""

from __future__ import annotations

import ast
import builtins
from collections.abc import Iterator
from dataclasses import dataclass, field

FUNCTION_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
COMPREHENSION_TYPES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_NESTED_SCOPES = (*FUNCTION_TYPES, ast.ClassDef, *COMPREHENSION_TYPES)

IMPORT = "import"
LOCAL = "local"
FIX_MODULES = frozenset({"subprocess", "ast", "json", "hashlib"})
BUILTIN_NAMES = frozenset(vars(builtins)) - {
    "__name__",
    "__doc__",
    "__package__",
    "__loader__",
    "__spec__",
}


@dataclass(eq=False)
class Scope:
    node: ast.AST
    parent: Scope | None
    # name -> set of (kind, import target or None)
    bindings: dict[str, set[tuple[str, str | None]]] = field(default_factory=dict)
    globals_: set[str] = field(default_factory=set)
    nonlocals: set[str] = field(default_factory=set)
    star_imports: list[str] = field(default_factory=list)

    @property
    def is_function(self) -> bool:
        return isinstance(self.node, FUNCTION_TYPES)

    @property
    def is_comprehension(self) -> bool:
        return isinstance(self.node, COMPREHENSION_TYPES)

    def bind(self, name: str, kind: str, target: str | None = None) -> None:
        self.bindings.setdefault(name, set()).add((kind, target))


class ScopeIndex:
    def __init__(self, tree: ast.Module) -> None:
        self.module = Scope(tree, None)
        self._scope_of: dict[int, Scope] = {}
        self._walrus_targets: set[int] = set()
        self._pending_nonlocal: list[tuple[Scope, str, str, str | None]] = []
        self._visit_body(self.module, tree.body)
        # Enclosing bindings may appear after the nested def, so resolve owners last.
        for scope, name, kind, target in self._pending_nonlocal:
            self._nonlocal_owner(scope, name).bind(name, kind, target)

    # -- queries -------------------------------------------------------------------------

    def scope_of(self, node: ast.AST) -> Scope:
        """Scope in which `node` executes."""
        return self._scope_of.get(id(node), self.module)

    def enclosing_function(self, node: ast.AST) -> ast.AST | None:
        scope: Scope | None = self.scope_of(node)
        while scope is not None and not scope.is_function:
            scope = scope.parent
        return scope.node if scope is not None else None

    def resolve_name(self, name: str, node: ast.AST) -> frozenset[str]:
        """All dotted paths `name` may refer to at `node`; empty for local values."""
        star: list[str] = []
        scope: Scope | None = self.scope_of(node)
        first = True
        while scope is not None:
            star.extend(scope.star_imports)
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent  # class scope invisible to nested scopes
                continue
            first = False
            if name in scope.globals_ and scope is not self.module:
                star.extend(self.module.star_imports)
                return self._resolve_in(self.module, name, star)
            if name in scope.nonlocals:
                scope = scope.parent
                while scope is not None and not scope.is_function:
                    scope = scope.parent
                continue
            if name in scope.bindings:
                return self._resolve_in(scope, name, star)
            scope = scope.parent
        return frozenset({name, *(f"{m}.{name}" for m in star)})

    def safe_module_reference(
        self, name: str, module: str, node: ast.AST, *, allow_unbound: bool = False
    ) -> bool:
        """Whether `name` can only denote a direct import of `module` at `node`.

        Templates may add an import for an unbound name. LLM rewrites must use an
        existing import. A star import or any non-import binding makes either unsafe.
        """
        scope: Scope | None = self.scope_of(node)
        first = True
        while scope is not None:
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent
                continue
            first = False
            if scope.star_imports:
                return False
            if name in scope.globals_ and scope is not self.module:
                scope = self.module
                continue
            if name in scope.nonlocals:
                scope = scope.parent
                while scope is not None and not scope.is_function:
                    scope = scope.parent
                continue
            if name in scope.bindings:
                return scope.bindings[name] == {(IMPORT, module)}
            scope = scope.parent
        return allow_unbound

    def safe_builtin_reference(self, name: str, node: ast.AST) -> bool:
        """Whether `name` must resolve to a builtin at this call site."""
        if name not in BUILTIN_NAMES:
            return False
        scope: Scope | None = self.scope_of(node)
        first = True
        while scope is not None:
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent
                continue
            first = False
            if (
                scope.star_imports
                or name in scope.bindings
                or name in scope.globals_
                or name in scope.nonlocals
            ):
                return False
            scope = scope.parent
        return True

    def safe_introduced_names(
        self,
        original: ast.Call,
        replacement: ast.AST,
        *,
        imports: tuple[str, ...] = (),
        sql_receiver: bool = False,
    ) -> bool:
        """Check new load names and every call target in a proposed replacement.

        Template fixes may add the declared imports. LLM fixes pass no imports,
        so their module names must already have a direct import at the call site.
        """
        original_names = {
            n.id
            for n in ast.walk(original)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        }
        replacement_names = {
            n.id
            for n in ast.walk(replacement)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
        }
        for name in replacement_names - original_names:
            if not self._safe_fix_name(name, original, imports):
                return False
        for node in ast.walk(replacement):
            if not isinstance(node, ast.Call):
                continue
            # SQL fixes keep the original receiver; it can be a local cursor.
            if (
                sql_receiver
                and node is replacement
                and isinstance(original.func, ast.Attribute)
                and ast.dump(node.func) == ast.dump(original.func)
            ):
                continue
            func = node.func
            while isinstance(func, (ast.Attribute, ast.Subscript)):
                func = func.value
            if isinstance(func, ast.Name) and not self._safe_fix_name(func.id, original, imports):
                return False
        return True

    def _safe_fix_name(self, name: str, original: ast.Call, imports: tuple[str, ...]) -> bool:
        if self.safe_builtin_reference(name, original):
            return True
        return any(
            self.safe_module_reference(
                name, module, original, allow_unbound=name == module and module in imports
            )
            for module in FIX_MODULES
        )

    def _resolve_in(self, scope: Scope, name: str, star: list[str]) -> frozenset[str]:
        kinds = scope.bindings.get(name)
        if not kinds:
            return frozenset({name, *(f"{m}.{name}" for m in star)})
        imports = {t for k, t in kinds if k == IMPORT and t}
        # A local binding may be conditional, so a star import can still supply the name.
        return frozenset(imports | {f"{m}.{name}" for m in star})

    # -- construction ----------------------------------------------------------------------

    def _visit_body(self, scope: Scope, body: list[ast.AST]) -> None:
        for stmt in body:
            for node in _same_scope_nodes(stmt):
                if isinstance(node, ast.Global):
                    scope.globals_.update(node.names)
                elif isinstance(node, ast.Nonlocal):
                    scope.nonlocals.update(node.names)
        for stmt in body:
            self._visit(stmt, scope)

    def _visit(self, node: ast.AST, scope: Scope) -> None:
        self._scope_of[id(node)] = scope
        if isinstance(node, COMPREHENSION_TYPES):
            self._enter_comprehension(node, scope)
            return
        if isinstance(node, _NESTED_SCOPES):
            self._enter_nested(node, scope)
            return
        self._bind(node, scope)
        for child in ast.iter_child_nodes(node):
            self._visit(child, scope)

    def _enter_nested(self, node: ast.AST, scope: Scope) -> None:
        outer: list[ast.AST] = list(getattr(node, "decorator_list", []))
        if isinstance(node, FUNCTION_TYPES):
            outer += list(node.args.defaults)
            outer += [d for d in node.args.kw_defaults if d is not None]
            if not isinstance(node, ast.Lambda):
                outer += _annotations(node)
        if isinstance(node, ast.ClassDef):
            outer += [*node.bases, *(k.value for k in node.keywords)]
        for part in outer:
            self._visit(part, scope)
        if not isinstance(node, ast.Lambda):
            self._bind_store(scope, node.name)  # type: ignore[attr-defined]

        inner = Scope(node, scope)
        if isinstance(node, FUNCTION_TYPES):
            for arg in _all_args(node.args):
                inner.bind(arg, LOCAL)
            body = [node.body] if isinstance(node, ast.Lambda) else node.body
        else:
            body = node.body  # type: ignore[attr-defined]
        self._visit_body(inner, body)

    def _enter_comprehension(self, node: ast.AST, scope: Scope) -> None:
        generators: list[ast.comprehension] = node.generators  # type: ignore[attr-defined]
        self._visit(generators[0].iter, scope)  # first iterable: enclosing scope
        inner = Scope(node, scope)
        for gen in generators:
            for target in ast.walk(gen.target):
                if isinstance(target, ast.Name):
                    inner.bind(target.id, LOCAL)
        rest: list[ast.AST] = []
        for i, gen in enumerate(generators):
            rest.append(gen.target)
            if i:
                rest.append(gen.iter)
            rest.extend(gen.ifs)
        if isinstance(node, ast.DictComp):
            rest += [node.key, node.value]
        else:
            rest.append(node.elt)  # type: ignore[attr-defined]
        for part in rest:
            self._visit(part, inner)

    def _bind(self, node: ast.AST, scope: Scope) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    self._bind_import(scope, a.asname, a.name)
                else:
                    top = a.name.split(".")[0]
                    self._bind_import(scope, top, top)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                for a in node.names:
                    if a.name == "*":
                        scope.star_imports.append(node.module)
                    else:
                        self._bind_import(scope, a.asname or a.name, f"{node.module}.{a.name}")
            else:  # relative import: project-local module, unknown to us
                for a in node.names:
                    if a.name == "*":
                        scope.star_imports.append("." * node.level + (node.module or ""))
                    else:
                        self._bind_store(scope, a.asname or a.name)
        elif isinstance(node, ast.NamedExpr):
            target_scope = scope
            while target_scope.is_comprehension and target_scope.parent is not None:
                target_scope = target_scope.parent
            self._bind_store(target_scope, node.target.id)
            self._walrus_targets.add(id(node.target))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if id(node) not in self._walrus_targets:
                self._bind_store(scope, node.id)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            self._bind_store(scope, node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind_store(scope, node.rest)

    def _owner(self, scope: Scope, name: str) -> Scope:
        """Scope that actually receives a binding of `name` made in `scope`."""
        if name in scope.globals_:
            return self.module
        return scope

    def _nonlocal_owner(self, scope: Scope, name: str) -> Scope:
        parent = scope.parent
        fallback = None
        while parent is not None:
            if parent.is_function:
                if name in parent.bindings and name not in parent.nonlocals:
                    return parent
                fallback = fallback or parent
            parent = parent.parent
        return fallback or scope

    def _bind_store(self, scope: Scope, name: str) -> None:
        self._add(scope, name, LOCAL, None)

    def _bind_import(self, scope: Scope, name: str, target: str) -> None:
        self._add(scope, name, IMPORT, target)

    def _add(self, scope: Scope, name: str, kind: str, target: str | None) -> None:
        if name in scope.nonlocals and name not in scope.globals_:
            self._pending_nonlocal.append((scope, name, kind, target))
        else:
            self._owner(scope, name).bind(name, kind, target)


def _same_scope_nodes(node: ast.AST) -> Iterator[ast.AST]:
    """`node` and its descendants, not descending into nested scopes (even if `node` is one)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, _NESTED_SCOPES):
            continue
        stack.extend(ast.iter_child_nodes(current))


def _all_args(args: ast.arguments) -> list[str]:
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    names += [a.arg for a in (args.vararg, args.kwarg) if a is not None]
    return names


def _annotations(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    args = func.args
    every = (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
    anns: list[ast.AST] = [a.annotation for a in every if a is not None and a.annotation]
    if func.returns is not None:
        anns.append(func.returns)
    return anns
