from __future__ import annotations

import ast
import textwrap

import pytest

from hackscan.plugins.base import FileContext


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


def test_star_import_survives_conditional_local_binding():
    ctx = ctx_for(
        """
        from os import *
        if safe:
            system = safe_handler
        system(command)
        """
    )
    assert "os.system" in all_names(ctx)["system(command)"]


def test_nonlocal_owner_bound_after_nested_def():
    ctx = ctx_for(
        """
        def outer():
            def middle():
                def inner():
                    nonlocal system
                    system(cmd)
                return inner
            from os import system
            return middle
        """
    )
    assert calls(ctx)["system(cmd)"] == "os.system"


@pytest.mark.parametrize(
    "code",
    [
        'str = eval\ndef f(value):\n    os.system(f"ls -- {value}")\n',
        'def f(value):\n    str = repr\n    os.system(f"ls -- {value}")\n',
        'from mylib import *\ndef f(value):\n    os.system(f"ls -- {value}")\n',
        'from .mylib import *\ndef f(value):\n    os.system(f"ls -- {value}")\n',
        'def f(value):\n    global str\n    os.system(f"ls -- {value}")\n',
        (
            "def outer(value):\n    str = repr\n    def f():\n        nonlocal str\n"
            '        os.system(f"ls -- {value}")\n'
        ),
    ],
)
def test_introduced_builtin_must_be_unbound_in_every_scope(code: str):
    ctx = ctx_for(code)
    call = next(n for n in ast.walk(ctx.tree) if isinstance(n, ast.Call))
    replacement = ast.parse("subprocess.call(['ls', '--', str(value)])", mode="eval").body
    assert not ctx.scopes.safe_introduced_names(call, replacement, imports=("subprocess",))


def test_introduced_names_accept_only_builtins_and_direct_modules():
    ctx = ctx_for("import ast as syntax\ndef f(value):\n    return eval(value)\n")
    call = next(n for n in ast.walk(ctx.tree) if isinstance(n, ast.Call))
    assert ctx.scopes.safe_introduced_names(
        call, ast.parse("syntax.literal_eval(value)", mode="eval").body
    )
    assert not ctx.scopes.safe_introduced_names(call, ast.parse("unknown(value)", mode="eval").body)


def test_existing_value_name_must_be_safe_when_replacement_calls_it():
    ctx = ctx_for('import os\nstr = eval\ndef f(value):\n    os.system(f"ls -- {value} {str}")\n')
    call = next(
        n
        for n in ast.walk(ctx.tree)
        if isinstance(n, ast.Call) and ctx.segment(n).startswith("os.system")
    )
    replacement = ast.parse("subprocess.call(['ls', '--', str(value), str(str)])", mode="eval").body
    assert not ctx.scopes.safe_introduced_names(call, replacement, imports=("subprocess",))


@pytest.mark.parametrize("module", ["subprocess", "ast", "hashlib", "json"])
def test_existing_value_name_must_be_safe_as_module_call_target(module: str):
    ctx = ctx_for(f"{module} = object()\ndef f(value):\n    return eval(({module}, value))\n")
    call = next(
        n
        for n in ast.walk(ctx.tree)
        if isinstance(n, ast.Call) and ctx.segment(n).startswith("eval")
    )
    replacement = ast.parse(f"{module}.call(value)", mode="eval").body
    assert not ctx.scopes.safe_introduced_names(call, replacement, imports=(module,))


def test_sql_receiver_exemption_requires_the_same_expression():
    ctx = ctx_for(
        "import sqlite3\ndef f(cur, other, uid):\n"
        '    cur.execute(f"SELECT * FROM t WHERE id = {uid} AND other = {other}")\n'
    )
    call = next(
        n
        for n in ast.walk(ctx.tree)
        if isinstance(n, ast.Call) and ctx.segment(n).startswith("cur.execute")
    )
    same = ast.parse(
        "cur.execute('SELECT * FROM t WHERE id = ? AND other = ?', (uid, other))", mode="eval"
    ).body
    changed = ast.parse(
        "other.execute('SELECT * FROM t WHERE id = ? AND other = ?', (uid, other))", mode="eval"
    ).body
    assert ctx.scopes.safe_introduced_names(call, same, sql_receiver=True)
    assert not ctx.scopes.safe_introduced_names(call, changed, sql_receiver=True)
