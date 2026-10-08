"""Lexical scopes and name bindings, following Python's scoping rules closely enough
for sink resolution (and, from M2, taint tracking).

- Function bodies (def/async def/lambda) are scopes; decorators, default values and
  annotations belong to the *enclosing* scope.
- Class bodies are scopes visible only to code directly in the class body, not to
  methods.
- A name is resolved at the use site: the innermost scope that binds it wins. If that
  binding is an import, the name resolves to the imported dotted path; any other binding
  (parameter, assignment, loop target, ...) makes it a local value of unknown origin.
  Names bound nowhere resolve to themselves (builtins).
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from dataclasses import dataclass, field

ScopeNode = ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef
FUNCTION_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_NESTED_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

IMPORT = "import"
LOCAL = "local"


@dataclass
class Scope:
    node: ScopeNode
    parent: Scope | None
    # name -> (kind, import target). kind is IMPORT or LOCAL.
    bindings: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    globals_: set[str] = field(default_factory=set)

    @property
    def is_function(self) -> bool:
        return isinstance(self.node, FUNCTION_TYPES)


class ScopeIndex:
    def __init__(self, tree: ast.Module) -> None:
        self.module = Scope(tree, None)
        self._scope_of: dict[int, Scope] = {}
        self._scopes: dict[int, Scope] = {id(tree): self.module}
        self._visit_scope(self.module)

    # -- queries -------------------------------------------------------------------------

    def scope_of(self, node: ast.AST) -> Scope:
        """Scope in which `node` executes."""
        return self._scope_of.get(id(node), self.module)

    def enclosing_function(self, node: ast.AST) -> ast.AST | None:
        scope: Scope | None = self.scope_of(node)
        while scope is not None and not scope.is_function:
            scope = scope.parent
        return scope.node if scope is not None else None

    def resolve_name(self, name: str, node: ast.AST) -> str | None:
        """Imported dotted path, the bare name for builtins, or None for local values."""
        scope: Scope | None = self.scope_of(node)
        first = True
        while scope is not None:
            # Class scopes are only visible to code directly in the class body.
            if isinstance(scope.node, ast.ClassDef) and not first:
                scope = scope.parent
                continue
            if name in scope.globals_:
                scope = self.module
                first = False
                continue
            if name in scope.bindings:
                kind, target = scope.bindings[name]
                return target if kind == IMPORT else None
            scope = scope.parent
            first = False
        return name

    def function_scopes(self) -> Iterator[Scope]:
        return (s for s in self._scopes.values() if s.is_function)

    # -- construction ----------------------------------------------------------------------

    def _visit_scope(self, scope: Scope) -> None:
        node = scope.node
        if isinstance(node, FUNCTION_TYPES):
            for arg in _all_args(node.args):
                scope.bindings[arg] = (LOCAL, None)
            body = [node.body] if isinstance(node, ast.Lambda) else node.body
        else:
            body = node.body
        for stmt in body:
            self._visit(stmt, scope)

    def _visit(self, node: ast.AST, scope: Scope) -> None:
        self._scope_of[id(node)] = scope
        if isinstance(node, _NESTED_SCOPES):
            self._enter_nested(node, scope)
            return
        self._bind(node, scope)
        for child in ast.iter_child_nodes(node):
            self._visit(child, scope)

    def _enter_nested(self, node: ast.AST, scope: Scope) -> None:
        # Parts evaluated in the enclosing scope.
        outer: list[ast.AST] = list(getattr(node, "decorator_list", []))
        if isinstance(node, FUNCTION_TYPES):
            outer += [d for d in node.args.defaults]
            outer += [d for d in node.args.kw_defaults if d is not None]
            if not isinstance(node, ast.Lambda):
                outer += _annotations(node)
        if isinstance(node, ast.ClassDef):
            outer += [*node.bases, *(k.value for k in node.keywords)]
        for part in outer:
            self._visit(part, scope)
        if not isinstance(node, ast.Lambda):
            _bind_name(scope, node.name)  # type: ignore[attr-defined]
        inner = Scope(node, scope)  # type: ignore[arg-type]
        self._scopes[id(node)] = inner
        self._visit_scope(inner)

    def _bind(self, node: ast.AST, scope: Scope) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    scope.bindings[a.asname] = (IMPORT, a.name)
                else:
                    top = a.name.split(".")[0]
                    scope.bindings[top] = (IMPORT, top)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                for a in node.names:
                    if a.name != "*":
                        scope.bindings[a.asname or a.name] = (IMPORT, f"{node.module}.{a.name}")
            else:  # relative imports: local module, treat as unknown local
                for a in node.names:
                    _bind_name(scope, a.asname or a.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            if isinstance(node, ast.Global):
                scope.globals_.update(node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id not in scope.globals_:
                _bind_name(scope, node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            _bind_name(scope, node.name)
        elif isinstance(node, ast.alias):
            pass


def _bind_name(scope: Scope, name: str) -> None:
    """A non-import binding shadows any import of the same name in this scope."""
    scope.bindings[name] = (LOCAL, None)


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
