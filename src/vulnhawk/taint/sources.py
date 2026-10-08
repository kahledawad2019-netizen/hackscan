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

# Attributes of `flask.request` that carry client data.
FLASK_REQUEST_ATTRS = frozenset(
    {
        "args",
        "form",
        "values",
        "json",
        "data",
        "cookies",
        "headers",
        "files",
        "get_json",
        "get_data",
        "view_args",
        "path",
        "full_path",
        "url",
        "query_string",
        "stream",
    }
)

# Attributes of a request parameter (Django/DRF/Starlette/FastAPI) that carry client data.
REQUEST_PARAM_ATTRS = frozenset(
    {
        # Django
        "GET",
        "POST",
        "body",
        "COOKIES",
        "META",
        "FILES",
        "headers",
        "path",
        "path_info",
        # DRF
        "data",
        "query_params",
        # Starlette / FastAPI
        "path_params",
        "cookies",
        "json",
        "form",
        "url",
        # Flask-style, when a request object is passed around
        "args",
        "values",
        "get_json",
        "get_data",
    }
)
REQUEST_PARAM_NAMES = frozenset({"request", "req"})

# Fully-qualified names whose value (attribute) or return value (call) is untrusted.
SOURCE_NAMES = {
    "sys.argv": "command-line arguments (sys.argv)",
    "sys.stdin": "standard input (sys.stdin)",
    "input": "user input (input())",
    "builtins.input": "user input (input())",
}

# Decorator method names that register an HTTP route handler.
ROUTE_DECORATORS = frozenset(
    {"route", "get", "post", "put", "patch", "delete", "head", "options", "api_route", "websocket"}
)


def flask_request_source(resolved: str) -> str | None:
    """`flask.request.args` -> description, for any resolved dotted name."""
    prefix = "flask.request."
    if resolved.startswith(prefix):
        attr = resolved[len(prefix) :].split(".", 1)[0]
        if attr in FLASK_REQUEST_ATTRS:
            return f"Flask request data (request.{attr})"
    return None


def is_route_handler(func: ast.AST) -> bool:
    """Decorated with `@<obj>.route(...)`, `@<obj>.get(...)`, etc."""
    for deco in getattr(func, "decorator_list", ()):
        target = deco.func if isinstance(deco, ast.Call) else deco
        if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
            return True
    return False
