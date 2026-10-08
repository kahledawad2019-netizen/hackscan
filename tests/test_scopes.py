from __future__ import annotations

import ast
import textwrap

from vulnhawk.plugins.base import FileContext


def ctx_for(code: str) -> FileContext:
    source = textwrap.dedent(code)
    return FileContext(path="m.py", source=source, tree=ast.parse(source))


def calls(ctx: FileContext) -> dict[str, str | None]:
    """Map call source text -> resolved name."""
    return {ctx.segment(n): ctx.call_name(n) for n in ast.walk(ctx.tree) if isinstance(n, ast.Call)}


def test_module_imports_and_aliases():
    ctx = ctx_for(
        """
        import os.path
        import subprocess as sp
        from hashlib import md5 as h
        os.path.join(a)
        sp.run(x)
        h(b)
        eval(c)
        """
    )
    assert calls(ctx) == {
        "os.path.join(a)": "os.path.join",
        "sp.run(x)": "subprocess.run",
        "h(b)": "hashlib.md5",
        "eval(c)": "eval",
    }


def test_function_local_import_does_not_leak():
    ctx = ctx_for(
        """
        def a():
            from os import system
            system(x)

        def b():
            system(y)
        """
    )
    resolved = calls(ctx)
    assert resolved["system(x)"] == "os.system"
    assert resolved["system(y)"] == "system"  # unbound here: not os.system


def test_parameters_and_assignments_shadow_imports():
    ctx = ctx_for(
        """
        import os

        def f(os, eval):
            os.system(x)
            eval(y)

        def g():
            os = make_fake()
            os.system(z)

        def h():
            os.system(w)
        """
    )
    resolved = calls(ctx)
    assert resolved["os.system(x)"] is None
    assert resolved["eval(y)"] is None
    assert resolved["os.system(z)"] is None
    assert resolved["os.system(w)"] == "os.system"


def test_class_scope_not_visible_to_methods():
    ctx = ctx_for(
        """
        import os

        class C:
            os = None
            os.system(a)

            def m(self):
                os.system(b)
        """
    )
    resolved = calls(ctx)
    assert resolved["os.system(a)"] is None
    assert resolved["os.system(b)"] == "os.system"


def test_global_declaration_uses_module_binding():
    ctx = ctx_for(
        """
        import subprocess

        def f():
            global subprocess
            subprocess.run(x)
        """
    )
    assert calls(ctx)["subprocess.run(x)"] == "subprocess.run"


def test_decorators_and_defaults_belong_to_enclosing_scope():
    ctx = ctx_for(
        """
        def outer(src):
            @deco(eval(src))
            def inner(x=eval(src)):
                return eval(x)
            return inner
        """
    )
    funcs = {
        ctx.segment(n): getattr(ctx.enclosing_function(n), "name", None)
        for n in ast.walk(ctx.tree)
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "eval"
    }
    assert funcs == {"eval(src)": "outer", "eval(x)": "inner"}
