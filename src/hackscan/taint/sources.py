"""Untrusted input sources: web frameworks, CLI and stdin.

Sources are matched three ways:
1. Resolved dotted names (`flask.request.args`, `sys.argv`, builtin `input`).
2. Request-object parameters: a parameter named `request`/`req` (Django, DRF, Starlette,
   FastAPI `Request`) whose request-data attributes are read.
3. Route handler parameters: every parameter of a function decorated with a routing
   decorator (`@app.route`, `@app.get`, `@router.post`, ...) is client-controlled
   (Flask path variables, FastAPI path/query/body parameters).
"""

from __future__ import annotations

import ast

from hackscan.taint import knowledge

# The source lists are data (knowledge.json); these names keep the built-in sets for compatibility.
# Analysis reads the active knowledge, which may also hold project notes.
FLASK_REQUEST_ATTRS = knowledge.BUILTIN.flask_request_attrs
REQUEST_PARAM_ATTRS = knowledge.BUILTIN.request_param_attrs
REQUEST_PARAM_NAMES = knowledge.BUILTIN.request_param_names
SOURCE_NAMES = knowledge.BUILTIN.source_names
ROUTE_DECORATORS = knowledge.BUILTIN.route_decorators


def flask_request_source(resolved: str) -> str | None:
    """`flask.request.args` -> description, for any resolved dotted name."""
    prefix = "flask.request."
    if resolved.startswith(prefix):
        attr = resolved[len(prefix) :].split(".", 1)[0]
        if attr in knowledge.active().flask_request_attrs:
            return f"Flask request data (request.{attr})"
    return None


def route_decorators_of(func: ast.AST) -> set[str]:
    """The routing decorator names (`@<obj>.route(...)`, `@<obj>.get(...)`, ...) on `func`."""
    found = set()
    for deco in getattr(func, "decorator_list", ()):
        target = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(target, ast.Attribute) and target.attr in knowledge.active().route_decorators:
            found.add(target.attr)
    return found


def is_route_handler(func: ast.AST) -> bool:
    """Decorated with `@<obj>.route(...)`, `@<obj>.get(...)`, etc."""
    return bool(route_decorators_of(func))
