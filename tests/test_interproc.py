from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from hackscan.analyzers.interproc import module_name, module_symbols
from hackscan.config import HackScanConfig
from hackscan.core.models import Status
from hackscan.core.pipeline import scan

UTILS = """
import os
import shlex
import sqlite3


def run(cmd):
    os.system("ls " + cmd)


def run_quoted(cmd):
    os.system("ls " + shlex.quote(cmd))


def run_int(n):
    os.system("kill " + str(int(n)))


def query(cur, value):
    cur.execute("SELECT * FROM t WHERE x = '%s'" % value)


def both(a, b):
    os.system(a)


def run_requoted(cmd):
    os.system('ls "' + shlex.quote(cmd) + '"')


def relay(x):
    run(x)


def recurse(x, n):
    if n:
        return recurse(x, n - 1)
    os.system(x)
"""
RUN_SINK = 'os.system("ls " + cmd)'
ONE_RUN = "import os\nfrom flask import request\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, code in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code), encoding="utf-8")
    return tmp_path


def findings(root: Path, **config):
    result = scan(root, HackScanConfig(**config))
    assert not result.errors, result.errors
    return result.findings


def status_at(root: Path, path: str, line_text: str, **config) -> Status:
    lines = (root / path).read_text(encoding="utf-8").splitlines()
    line = next(i for i, text in enumerate(lines, 1) if line_text in text)
    matches = [
        f
        for f in findings(root, **config)
        if f.location.path == path and f.location.start_line == line
    ]
    assert len(matches) == 1, matches
    return matches[0].status


def caller(imports: str, *body: str) -> str:
    """A `views.py` module: the imports, then `def v():` running each body line."""
    return "\n".join([imports, "", "", "def v(cur=None):", *(f"    {b}" for b in body), ""])


def views(code: str) -> dict[str, str]:
    return {
        "app/__init__.py": "",
        "app/utils.py": UTILS,
        "app/views.py": "import os\nfrom flask import request\n" + code,
    }


@pytest.mark.parametrize(
    ("imports", "call", "sink"),
    [
        ("from . import utils", "utils.run(request.args['q'])", RUN_SINK),
        ("from .utils import run", "run(request.args['q'])", RUN_SINK),
        ("from app.utils import run", "run(request.args['q'])", RUN_SINK),
        ("import app.utils", "app.utils.run(request.args['q'])", RUN_SINK),
        ("from app import utils as u", "u.run(cmd=request.args['q'])", RUN_SINK),
        ("from .utils import relay", "relay(request.args['q'])", RUN_SINK),
        ("from .utils import recurse", "recurse(request.args['q'], 3)", "os.system(x)"),
        ("from .utils import query", "query(cur, request.args['q'])", "cur.execute"),
    ],
)
def test_untrusted_argument_confirms_sink_in_callee(tmp_path, imports, call, sink):
    root = project(tmp_path, views(caller(imports, call)))
    assert status_at(root, "app/utils.py", sink) is Status.CONFIRMED


def test_confirmation_explains_the_path(tmp_path):
    root = project(tmp_path, views(caller("from .utils import relay", "relay(request.args['q'])")))
    (finding,) = [f for f in findings(root) if f.status is Status.CONFIRMED]
    steps = [e.message for e in finding.evidence if e.kind == "taint_step"]
    assert len(steps) == 1
    assert "at app/views.py:7 reaches parameter `cmd` of `run`." in steps[0], steps
    verdicts = [e.message for e in finding.evidence if e.kind == "taint_verdict"]
    assert verdicts == ["Untrusted input reaches the sink through calls."]
    assert finding.confidence > 50


def test_without_untrusted_callers_the_sink_stays_a_candidate(tmp_path):
    root = project(tmp_path, views(caller("from .utils import run", "run('-la')")))
    # Confirmation only: a constant caller never suppresses (other callers may exist).
    assert status_at(root, "app/utils.py", RUN_SINK) is Status.CANDIDATE


@pytest.mark.parametrize(
    ("imports", "body"),
    [
        ("from .utils import run_quoted", ["run_quoted(request.args['q'])"]),
        ("from .utils import run_int", ["run_int(request.args['q'])"]),
        ("from .utils import run", ["run(str(int(request.args['q'])))"]),
        ("from .utils import both", ["both('ls', request.args['q'])"]),
        # after `*args` the position of a value is unknown
        ("from .utils import both", ["both(*['ls'], request.args['q'])"]),
        ("from .utils import run", ["request.args['q']", "run('-la')"]),
    ],
)
def test_sanitized_or_unrelated_values_do_not_confirm(tmp_path, imports, body):
    root = project(tmp_path, views(caller(imports, *body)))
    for f in findings(root):
        if f.location.path == "app/utils.py":
            assert f.status is not Status.CONFIRMED, f


def test_sanitizer_class_matters(tmp_path):
    # shlex.quote protects commands, not SQL.
    imports = "import shlex\nfrom .utils import query"
    root = project(tmp_path, views(caller(imports, "query(cur, shlex.quote(request.args['q']))")))
    assert status_at(root, "app/utils.py", "cur.execute") is Status.CONFIRMED


def test_quoted_value_reembedded_in_quotes_confirms(tmp_path):
    imports = "import shlex\nfrom .utils import run"
    call = "run('\"' + shlex.quote(request.args['q']) + '\"')"
    root = project(tmp_path, views(caller(imports, call)))
    assert status_at(root, "app/utils.py", RUN_SINK) is Status.CONFIRMED


def test_callee_requoting_its_parameter_inside_quotes_confirms(tmp_path):
    imports = "from .utils import run_requoted"
    root = project(tmp_path, views(caller(imports, "run_requoted(request.args['q'])")))
    assert status_at(root, "app/utils.py", "'ls \"' + shlex") is Status.CONFIRMED


def test_returned_source_confirms_caller_sink(tmp_path):
    files = {
        "lib.py": """
            from flask import request

            def user_value():
                return request.args.get("q")

            def ident(x):
                return x

            def clean():
                return int(request.args.get("q"))
        """,
        "main.py": """
            import os
            import lib
            from flask import request

            def a():
                os.system(lib.user_value())

            def b():
                os.system(lib.ident("ls"))

            def c():
                os.system("kill " + str(lib.clean()))

            def d():
                return lib.ident(request.args.get("q"))
        """,
    }
    root = project(tmp_path, files)
    assert status_at(root, "main.py", "lib.user_value()") is Status.CONFIRMED
    # Parameters of the callee are not sources of their own; sanitized returns stay safe.
    assert status_at(root, "main.py", "lib.ident") is Status.CANDIDATE
    assert status_at(root, "main.py", "lib.clean") is Status.CANDIDATE


def test_same_file_calls_are_linked(tmp_path):
    root = project(tmp_path, {"one.py": ONE_RUN + "def view():\n    run(request.args['q'])\n"})
    assert status_at(root, "one.py", "os.system(cmd)") is Status.CONFIRMED


@pytest.mark.parametrize(
    "code",
    [
        # a local binding shadows the module-level function
        "def view():\n    run = print\n    run(request.args['q'])\n",
        # the module name is rebound
        "run = print\n\n\ndef view():\n    run(request.args['q'])\n",
        # a parameter shadows it
        "def view(run):\n    run(request.args['q'])\n",
        # rebound through `global`
        "def other():\n    global run\n    run = print\n\n\n"
        "def view():\n    run(request.args['q'])\n",
        # methods are not linked
        "class C:\n    def run(self, cmd):\n        pass\n\n\n"
        "def view(c):\n    c.run(request.args['q'])\n",
        # pattern captures bind locally
        "def view(value):\n    match value:\n        case {'cb': run}:\n"
        "            run(request.args['q'])\n",
        "def view(value):\n    match value:\n        case [*run]:\n"
        "            run(request.args['q'])\n",
        "def view(value):\n    match value:\n        case {**run}:\n"
        "            run(request.args['q'])\n",
        # walrus in defaults evaluated at module level rebinds it
        "def other(*, cb=(run := print)):\n    pass\n\n\nrun(request.args['q'])\n",
        "def other(cb=(run := print)):\n    pass\n\n\nrun(request.args['q'])\n",
        "other = lambda cb=(run := print): 0\nrun(request.args['q'])\n",
        "def other(x: (run := print)):\n    pass\n\n\nrun(request.args['q'])\n",
        "class K((run := object)):\n    pass\n\n\nrun(request.args['q'])\n",
        # `*args` hides the positions
        "def view():\n    run(*[request.args['q']])\n",
        # unknown keyword
        "def view():\n    run(other=request.args['q'])\n",
    ],
)
def test_ambiguous_callees_are_not_linked(tmp_path, code):
    root = project(tmp_path, {"one.py": ONE_RUN + code})
    assert status_at(root, "one.py", "os.system(cmd)") is Status.CANDIDATE


def test_decorated_and_conditional_functions_are_not_linked(tmp_path):
    files = {
        "lib.py": """
            import os

            def deco(f):
                return f

            @deco
            def run(cmd):
                os.system(cmd)

            if True:
                def run2(cmd):
                    os.system(cmd)
        """,
        "main.py": """
            from flask import request
            from lib import run, run2

            def view():
                run(request.args["q"])
                run2(request.args["q"])
        """,
    }
    root = project(tmp_path, files)
    assert [f.status for f in findings(root)] == [Status.CANDIDATE, Status.CANDIDATE]


def test_star_import_module_is_not_linked(tmp_path):
    files = {
        "lib.py": "import os\nfrom shlex import *\n\n\ndef run(cmd):\n    os.system(cmd)\n",
        "main.py": caller(
            "from flask import request\nfrom lib import run", "run(request.args['q'])"
        ),
    }
    root = project(tmp_path, files)
    assert status_at(root, "lib.py", "os.system(cmd)") is Status.CANDIDATE


def test_ambiguous_module_names_are_not_linked(tmp_path):
    sink = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
    files = {
        "a/utils.py": sink,
        "b/utils.py": sink,
        "main.py": caller(
            "from flask import request\nfrom utils import run", "run(request.args['q'])"
        ),
    }
    root = project(tmp_path, files)
    assert [f.status for f in findings(root)] == [Status.CANDIDATE, Status.CANDIDATE]


def test_src_layout_and_reexport(tmp_path):
    files = {
        "src/pkg/__init__.py": "from .core import run\n",
        "src/pkg/core.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n",
        "src/pkg/web.py": caller(
            "from flask import request\nimport pkg", "pkg.run(request.args['q'])"
        ),
    }
    root = project(tmp_path, files)
    assert status_at(root, "src/pkg/core.py", "os.system(cmd)") is Status.CONFIRMED


def test_positional_only_parameter_is_not_bound_by_keyword(tmp_path):
    code = ONE_RUN.replace("def run(cmd):", "def run(cmd, /, **kw):")
    code += "def view():\n    run('ls', cmd=request.args['q'])\n"
    root = project(tmp_path, {"one.py": code})
    assert status_at(root, "one.py", "os.system(cmd)") is Status.CANDIDATE


def test_inline_suppression_wins(tmp_path):
    files = views(caller("from .utils import run", "run(request.args['q'])"))
    files["app/utils.py"] = UTILS.replace(RUN_SINK, RUN_SINK + "  # hackscan: ignore")
    root = project(tmp_path, files)
    assert status_at(root, "app/utils.py", RUN_SINK) is Status.SUPPRESSED


def test_linking_follows_the_taint_switch(tmp_path):
    root = project(tmp_path, views(caller("from .utils import run", "run(request.args['q'])")))
    assert status_at(root, "app/utils.py", RUN_SINK, taint=False) is Status.CANDIDATE


def test_parallel_and_serial_linking_agree(tmp_path):
    files = {
        f"m{i}.py": f"import os\n\n\ndef run{i}(cmd):\n    os.system(cmd)\n" for i in range(20)
    }
    imports = "\n".join(
        ["from flask import request", *(f"from m{i} import run{i}" for i in range(20))]
    )
    files["main.py"] = caller(imports, *(f"run{i}(request.args['q'])" for i in range(0, 20, 2)))
    root = project(tmp_path, files)
    serial = findings(root, jobs=1)
    parallel = findings(root, jobs=4)
    assert serial == parallel
    confirmed = {f.location.path for f in serial if f.status is Status.CONFIRMED}
    assert confirmed == {f"m{i}.py" for i in range(0, 20, 2)}


@pytest.mark.parametrize(
    ("path", "module"),
    [
        ("a.py", "a"),
        ("pkg/__init__.py", "pkg"),
        ("pkg/sub/mod.py", "pkg.sub.mod"),
        ("__init__.py", "__init__"),
        ("tool.pyw", "tool"),
    ],
)
def test_module_name(path, module):
    assert module_name(path) == module


def test_module_symbols_resolve_relative_imports():
    source = "\n".join(
        [
            "from . import a",
            "from ..b import c as d",
            "from .e.f import g",
            "import x.y",
            "import x.z as z",
            "def run():",
            "    pass",
        ]
    )
    assert module_symbols(ast.parse(source), "pkg/sub/mod.py") == {
        "a": ("import", "pkg.sub.a"),
        "d": ("import", "pkg.b.c"),
        "g": ("import", "pkg.sub.e.f.g"),
        "x": ("import", "x"),
        "z": ("import", "x.z"),
        "run": ("def", "run"),
    }
    # Beyond the top-level package the import cannot be resolved.
    assert "q" not in module_symbols(ast.parse("from ... import q\n"), "pkg/mod.py")
