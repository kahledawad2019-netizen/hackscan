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


def all_names(ctx: FileContext) -> dict[str, frozenset[str]]:
    return {
        ctx.segment(n): ctx.call_names(n) for n in ast.walk(ctx.tree) if isinstance(n, ast.Call)
    }


def test_module_level_global_does_not_hang():
    ctx = ctx_for(
        """
        global os
        import os
        os.system(cmd)
        """
    )
    assert calls(ctx)["os.system(cmd)"] == "os.system"


def test_comprehension_targets_do_not_leak():
    ctx = ctx_for(
        """
        import os
        [os.system(a) for os in items]
        os.system(b)
        """
    )
    resolved = calls(ctx)
    assert resolved["os.system(a)"] is None
    assert resolved["os.system(b)"] == "os.system"


def test_comprehension_in_class_does_not_see_class_bindings():
    ctx = ctx_for(
        """
        import os

        class C:
            os = None
            items = [os.system(x) for x in range(3)]
        """
    )
    assert calls(ctx)["os.system(x)"] == "os.system"


def test_comprehension_first_iterable_uses_enclosing_scope():
    ctx = ctx_for(
        """
        import os

        class C:
            os = None
            items = [x for x in os.listdir(p)]
        """
    )
    assert calls(ctx)["os.listdir(p)"] is None  # class-level `os` is visible here


def test_later_rebinding_keeps_import_possible():
    ctx = ctx_for(
        """
        import os
        os.system(a)
        os = replacement
        """
    )
    assert calls(ctx)["os.system(a)"] == "os.system"


def test_try_except_and_conditional_import_fallbacks():
    ctx = ctx_for(
        """
        try:
            import subprocess
        except ImportError:
            subprocess = None
        if flag:
            from os import system
        else:
            system = print
        subprocess.run(a, shell=True)
        system(b)
        """
    )
    resolved = all_names(ctx)
    assert resolved["subprocess.run(a, shell=True)"] == {"subprocess.run"}
    assert resolved["system(b)"] == {"os.system"}


def test_module_level_walrus_keeps_import_possible():
    ctx = ctx_for(
        """
        import os
        os.system(a)
        if (os := other()):
            pass
        """
    )
    assert calls(ctx)["os.system(a)"] == "os.system"


def test_walrus_in_comprehension_binds_enclosing_function():
    ctx = ctx_for(
        """
        def f():
            [(cmd := x) for x in items]
            return cmd
        """
    )
    func = ctx.tree.body[0]
    scope = ctx.scopes.scope_of(func.body[0])
    assert "cmd" in scope.bindings
    assert "x" not in scope.bindings


def test_nonlocal_refers_to_enclosing_function():
    ctx = ctx_for(
        """
        def outer():
            from os import system

            def inner():
                nonlocal system
                system(a)
                system = print

            system(b)
            return inner
        """
    )
    resolved = calls(ctx)
    assert resolved["system(a)"] == "os.system"
    assert resolved["system(b)"] == "os.system"


def test_star_import_adds_possible_names():
    ctx = ctx_for(
        """
        from os import *
        system(cmd)
        eval(x)
        """
    )
    resolved = all_names(ctx)
    assert "os.system" in resolved["system(cmd)"]
    assert "eval" in resolved["eval(x)"]
