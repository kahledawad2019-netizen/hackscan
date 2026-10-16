"""A `confirmed` finding needs an established flow: untrusted data reaches the sink through
operations the analysis models. Through a call nobody models the flow is only assumed: the
finding stays a candidate (never suppressed, never constant) and the call is recorded."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from hackscan.analyzers.ast_pass import analyze_source
from hackscan.config import HackScanConfig, load
from hackscan.core.models import ASSUMED_VERDICT, CONFIRMED_VERDICT, Status
from hackscan.core.pipeline import scan
from hackscan.plugins.loader import builtin_plugins

HEADER = "import base64, json, os, re, subprocess, urllib.parse\nfrom flask import request\n\n"


def one(body: str):
    code = HEADER + textwrap.dedent(body)
    findings = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.vuln_class in ("sqli", "cmdi", "codei")
    ]
    assert len(findings) == 1, findings
    return findings[0]


def project(tmp_path: Path, files: dict[str, str]):
    for name, code in files.items():
        (tmp_path / name).write_text(textwrap.dedent(code), encoding="utf-8")
    return scan(tmp_path, HackScanConfig(jobs=1)).findings


def at(findings, path: str, sink: str):
    """The finding whose sink expression is `sink`."""
    (f,) = [f for f in findings if f.location.path == path and f.sink == sink]
    return f


def notes(f) -> list[str]:
    return [e.message for e in f.evidence if e.kind == "taint_step"]


ASSUMED = {
    "unknown function": """
        def f():
            os.system(build(request.args['q']))
        """,
    "unknown method on an unrelated object": """
        def f(self):
            os.system(self.builder.make(request.args['q']))
        """,
    "method of untrusted data that is not modelled": """
        def f():
            os.system(request.args['q'].render())
        """,
    "stored in an object by an unmodelled method": """
        def f(registry):
            registry.register(request.args['q'])
            os.system(registry)
        """,
    "a shadowed modelled name": """
        def f():
            loads = lambda s: "ls"
            os.system(loads(request.args['q']))
        """,
    "an option, not the data argument": """
        def f(text):
            os.system(json.loads(text, object_hook=request.args['hook']))
        """,
    "a non-data positional argument": """
        def f():
            os.system(re.sub(request.args['p'], '', 'ls'))
        """,
    "a mutator of an object, not a container": """
        def f(box):
            box.append(request.args['q'])
            os.system(box)
        """,
    "a data argument after *args": """
        def f(parts):
            os.system(re.sub(*parts, request.args['q']))
        """,
}

ESTABLISHED = {
    "direct": """
        def f():
            os.system("ls " + request.args['q'])
        """,
    "request accessor method": """
        def f():
            os.system("ls " + request.args.get('q', ''))
        """,
    "request data method": """
        def f():
            os.system("ls " + request.get_json()['q'])
        """,
    "json.loads": """
        def f():
            os.system(json.loads(request.data)['cmd'])
        """,
    "base64 decoding": """
        def f():
            os.system(base64.b64decode(request.args['q']).decode())
        """,
    "url decoding": """
        def f():
            os.system(urllib.parse.unquote(request.args['q']))
        """,
    "re.sub keeps the string": """
        def f():
            os.system(re.sub(r'^www\\.', '', request.args['q']))
        """,
    "path assembly": """
        def f():
            os.system(os.path.join('/opt', request.args['q']))
        """,
    "list append": """
        def f():
            parts = ['ls']
            parts.append(request.args['q'])
            os.system(' '.join(parts))
        """,
    "an established path next to an assumed one": """
        def f():
            os.system(request.args['a'] + build(request.args['b']))
        """,
}


@pytest.mark.parametrize("body", ASSUMED.values(), ids=ASSUMED.keys())
def test_assumed_flow_stays_a_candidate(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None
    assert any("not modelled" in n for n in notes(f)), notes(f)


@pytest.mark.parametrize("body", ESTABLISHED.values(), ids=ESTABLISHED.keys())
def test_established_flow_confirms(body):
    f = one(body)
    assert f.status is Status.CONFIRMED
    assert all("not modelled" not in n for n in notes(f))


def test_compile_keeps_the_flow():
    # (code that `eval` runs is outside the model: that it rebinds `compile` is not assumed;
    # an explicit namespace write is, see the round-2 tests)
    code = HEADER + "def f():\n    eval(compile(request.args['q'], '<q>', 'eval'))\n"
    findings = analyze_source(code, "app.py", builtin_plugins()).findings
    (f,) = [f for f in findings if f.sink.startswith("eval(")]
    assert f.status is Status.CONFIRMED


def test_assumed_constant_is_still_not_constant():
    f = one(
        """
        def f():
            os.system(build("ls"))
        """
    )
    assert f.status is Status.CANDIDATE  # an unknown call's result is never provably constant


def test_established_steps_only_in_a_confirmation():
    f = one(
        """
        def f():
            os.system(request.args['a'] + build(request.args['b']))
        """
    )
    assert f.status is Status.CONFIRMED
    assert len(notes(f)) == 1  # the direct source only, not the assumed one


# -- across functions ----------------------------------------------------------------------

HELPERS = """
from flask import request
import os


def relay(value):
    return value


def constant(value):
    return "ls"


def opaque(value):
    return build(value)


def run(cmd):
    os.system(cmd)
"""


def test_returned_argument_is_established_per_call_site(tmp_path):
    findings = project(
        tmp_path,
        {
            "app.py": HELPERS
            + """

def tainted():
    os.system(relay(request.args['q']))


def clean():
    os.system(relay("ls -l"))
""",
        },
    )
    tainted = at(findings, "app.py", "os.system(relay(request.args['q']))")
    assert tainted.status is Status.CONFIRMED
    # The same helper called with a constant elsewhere: the source of the other call site
    # never flows back into this result.
    clean = at(findings, "app.py", 'os.system(relay("ls -l"))')
    assert clean.status is not Status.CONFIRMED


def test_unrelated_return_does_not_confirm(tmp_path):
    findings = project(
        tmp_path,
        {"app.py": HELPERS + "\n\ndef view():\n    os.system(constant(request.args['q']))\n"},
    )
    f = at(findings, "app.py", "os.system(constant(request.args['q']))")
    assert f.status is not Status.CONFIRMED


def test_assumed_flow_does_not_become_established_across_a_function(tmp_path):
    findings = project(
        tmp_path,
        {"app.py": HELPERS + "\n\ndef view():\n    os.system(opaque(request.args['q']))\n"},
    )
    f = at(findings, "app.py", "os.system(opaque(request.args['q']))")
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_parameter_reached_through_an_unmodelled_call_records_the_path(tmp_path):
    findings = project(
        tmp_path,
        {"app.py": HELPERS + "\n\ndef view():\n    run(build(request.args['q']))\n"},
    )
    f = at(findings, "app.py", "os.system(cmd)")
    assert f.status is Status.CANDIDATE
    assert any("may reach parameter `cmd` of `run`" in n for n in notes(f)), notes(f)


def test_parameter_reached_directly_confirms(tmp_path):
    findings = project(
        tmp_path,
        {"app.py": HELPERS + "\n\ndef view():\n    run(request.args['q'])\n"},
    )
    f = at(findings, "app.py", "os.system(cmd)")
    assert f.status is Status.CONFIRMED
    assert any("reaches parameter `cmd` of `run`" in n for n in notes(f))


# -- review round 1 --------------------------------------------------------------------------


def test_nested_returns_keep_their_call_site(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def ident(x):\n    return x\n\n\n"
        "def wrapper(x):\n    return ident(x)\n\n\n"
        "def tainted():\n    os.system(wrapper(request.data))\n\n\n"
        "def constant():\n    os.system(wrapper('ls'))\n\n\n"
        "def opaque():\n    os.system(wrapper(build(request.data)))\n"
    )
    findings = project(tmp_path, {"app.py": code})
    assert at(findings, "app.py", "os.system(wrapper(request.data))").status is Status.CONFIRMED
    assert at(findings, "app.py", "os.system(wrapper('ls'))").status is not Status.CONFIRMED
    opaque = at(findings, "app.py", "os.system(wrapper(build(request.data)))")
    assert opaque.status is Status.CANDIDATE


UNSTABLE = {
    "a replaced json.loads": """
        json.loads = lambda x: "ls"

        def f():
            os.system(json.loads(request.data))
        """,
    "a replaced re.sub": """
        re.sub = lambda *a: "ls"

        def f():
            os.system(re.sub("x", "", request.args['q']))
        """,
    "a replaced shlex.quote": """
        import shlex
        shlex.quote = lambda x: "ls"

        def f():
            os.system(shlex.quote(request.args['q']))
        """,
}


@pytest.mark.parametrize("body", UNSTABLE.values(), ids=UNSTABLE.keys())
def test_a_replaced_model_is_not_modelled(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


OBJECTS = {
    "get on an object after a field store": """
        def f(box):
            box.data = request.args['q']
            os.system(box.get())
        """,
    "get_json on an object after a field store": """
        def f(box):
            box.data = request.args['q']
            os.system(box.get_json())
        """,
    "a no-op update on an object": """
        def f(box):
            box.update(request.data)
            os.system(box.read())
        """,
    "a field read back": """
        def f(box):
            box.cmd = request.args['q']
            os.system(box.cmd)
        """,
    "an item store into an object": """
        def f(box):
            box['cmd'] = request.args['q']
            os.system(box.get('other'))
        """,
}


@pytest.mark.parametrize("body", OBJECTS.values(), ids=OBJECTS.keys())
def test_objects_never_carry_established_data(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


CONTAINERS = {
    "dict item store": """
        def f():
            options = {}
            options['cmd'] = request.args['q']
            os.system(options['cmd'])
        """,
    "dict default": """
        def f():
            os.system({}.get('q', request.args['q']))
        """,
    "accessor on a request mapping": """
        def f():
            os.system(request.form.get('q'))
        """,
    "accessor on request JSON": """
        def f():
            data = request.get_json()
            os.system(data.get('q'))
        """,
}


@pytest.mark.parametrize("body", CONTAINERS.values(), ids=CONTAINERS.keys())
def test_containers_and_request_data_stay_established(body):
    assert one(body).status is Status.CONFIRMED


def test_accessor_on_a_parameter_follows_the_caller(tmp_path):
    code = (
        "import os, sys\n\n\n"
        "def run_hook(hooks, name):\n    os.system(hooks.get(name, 'true'))\n\n\n"
        "def main():\n    run_hook({'custom': sys.argv[1]}, 'custom')\n"
    )
    findings = project(tmp_path, {"app.py": code})
    assert at(findings, "app.py", "os.system(hooks.get(name, 'true'))").status is Status.CONFIRMED


SANITIZED_PART = {
    "concatenation": """
        def f():
            safe = str(int(request.args['safe']))
            opaque = build(request.args['opaque'])
            os.system(safe + opaque)
        """,
    "branches": """
        def f(choice):
            if choice:
                value = str(int(request.args['safe']))
            else:
                value = build(request.args['opaque'])
            os.system(value)
        """,
}


@pytest.mark.parametrize("body", SANITIZED_PART.values(), ids=SANITIZED_PART.keys())
def test_a_sanitized_source_does_not_confirm(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_sanitized_source_does_not_confirm_across_functions(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def run(cmd):\n    os.system(cmd)\n\n\n"
        "def view():\n"
        "    run(str(int(request.args['safe'])) + build(request.args['opaque']))\n"
    )
    f = at(project(tmp_path, {"app.py": code}), "app.py", "os.system(cmd)")
    assert f.status is Status.CANDIDATE


def test_a_linked_confirmation_drops_the_local_assumption(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def ident(x):\n    return x\n\n\n"
        "def view():\n    os.system(ident(request.data))\n"
    )
    f = at(project(tmp_path, {"app.py": code}), "app.py", "os.system(ident(request.data))")
    assert f.status is Status.CONFIRMED
    assert all("not modelled" not in n for n in notes(f)), notes(f)


def test_the_unmodelled_call_is_named_across_functions(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def opaque(x):\n    return actual_transform(x)\n\n\n"
        "def run(cmd):\n    os.system(cmd)\n\n\n"
        "def view():\n    run(opaque(request.data))\n"
    )
    f = at(project(tmp_path, {"app.py": code}), "app.py", "os.system(cmd)")
    assert f.status is Status.CANDIDATE
    assert any("`actual_transform` (app.py:6)" in n for n in notes(f)), notes(f)


KEYWORDS = {
    "json.loads(s=...)": """
        def f():
            os.system(json.loads(s=request.data))
        """,
    "re.sub(string=...)": """
        def f():
            os.system(re.sub(pattern="x", repl="", string=request.args['q']))
        """,
}


@pytest.mark.parametrize("body", KEYWORDS.values(), ids=KEYWORDS.keys())
def test_keyword_data_arguments_stay_established(body):
    assert one(body).status is Status.CONFIRMED


NOTED_ATTR = (
    "knowledge:\n  - type: request_param_attr\n    value: render\n"
    "    rationale: r\n    evidence: e\n"
)


def test_a_noted_request_attribute_does_not_establish_its_method(tmp_path):
    code = "import os\n\n\ndef view(request):\n    os.system(request.render())\n"
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    (tmp_path / ".hackscan.yml").write_text(NOTED_ATTR, encoding="utf-8")
    (f,) = [f for f in scan(tmp_path, load(tmp_path)).findings if f.vuln_class == "cmdi"]
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_marks_keep_one_example_call_and_every_class():
    from hackscan.analyzers.interproc import ASSUMED, is_assumed, join_marks

    joined = join_marks(
        frozenset({"sqli", f"{ASSUMED}:`b` (app.py:2)"}),
        frozenset({"xss", f"{ASSUMED}:`a` (app.py:1)"}),
    )
    assert joined == {"sqli", "xss", f"{ASSUMED}:`a` (app.py:1)"}
    assert is_assumed(joined)
    assert join_marks(frozenset({"sqli"}), frozenset()) == {"sqli"}


def test_many_unmodelled_calls_do_not_multiply_the_pairs():
    # 12 choices between two unmodelled calls: 4096 combinations of calls on the way, but a
    # value keeps one example call per path
    chain = "".join(f"    x = a{i}(x) if c else b{i}(x)\n" for i in range(12))
    code = HEADER + "def run(x, c):\n" + chain + "    os.system(x)\n"
    result = analyze_source(code, "app.py", builtin_plugins(), link=True)
    (flow,) = result.facts.sinks.values()
    assert 0 < len(flow.symbols) <= 25, len(flow.symbols)  # linear, not 2 ** 12


def test_nested_returns_through_a_loop(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def ident(x):\n    return x\n\n\n"
        "def pick(x, y):\n    return y\n\n\n"
        "def wrapper(x, y, n):\n"
        "    while n:\n        x = ident(pick(x, ident(y)))\n"
        "    return ident(x)\n\n\n"
        "def tainted():\n    os.system(wrapper('ls', request.data, 3))\n\n\n"
        "def constant():\n    os.system(wrapper('ls', 'pwd', 3))\n"
    )
    findings = project(tmp_path, {"app.py": code})
    assert (
        at(findings, "app.py", "os.system(wrapper('ls', request.data, 3))").status
        is Status.CONFIRMED
    )
    assert (
        at(findings, "app.py", "os.system(wrapper('ls', 'pwd', 3))").status is not Status.CONFIRMED
    )


def test_a_summary_cut_at_a_cycle_is_not_reused(tmp_path):
    # Summarizing `y = ident(z)` reaches `x = ident(y)`, whose argument depends on `y`
    # again: `x` is cut there, so it must be summarized afresh where `x` itself is returned.
    code = (
        "from flask import request\nimport os, shlex\n\n\n"
        "def ident(x):\n    return x\n\n\n"
        "def w(p, q, n):\n"
        "    z = p\n    y = q\n    x = ''\n"
        "    while n:\n        y = ident(z)\n        x = ident(y)\n        z = x\n"
        "    return shlex.quote(y) + x\n\n\n"
        "def view():\n    os.system(w(request.data, 'q', 3))\n"
    )
    f = at(project(tmp_path, {"app.py": code}), "app.py", "os.system(w(request.data, 'q', 3))")
    assert f.status is Status.CONFIRMED


def test_a_call_nested_in_an_argument_is_linked(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def ident(x):\n    return x\n\n\n"
        "def twice(x):\n    return ident(ident(x))\n\n\n"
        "def tainted():\n    os.system(twice(request.data))\n\n\n"
        "def constant():\n    os.system(twice('ls'))\n"
    )
    findings = project(tmp_path, {"app.py": code})
    assert at(findings, "app.py", "os.system(twice(request.data))").status is Status.CONFIRMED
    assert at(findings, "app.py", "os.system(twice('ls'))").status is not Status.CONFIRMED


def test_two_calls_of_one_callee_keep_their_own_arguments(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def ident(x):\n    return x\n\n\n"
        "def pick(x, y):\n    return y\n\n\n"
        "def g(a):\n    return pick(ident(a), ident('ls'))\n\n\n"
        "def view():\n    os.system(g(request.data))\n"
    )
    f = at(project(tmp_path, {"app.py": code}), "app.py", "os.system(g(request.data))")
    assert f.status is not Status.CONFIRMED


# -- review round 2 --------------------------------------------------------------------------

ROUND2_ASSUMED = {
    "a default of an arbitrary object's get": """
        def f(box):
            os.system(box.get('q', request.data))
        """,
    "a mutator of a container's element": """
        def f():
            boxes = [make()]
            boxes[0].update(request.data)
            os.system(boxes[0].get('q'))
        """,
    "an item store into a container's element": """
        def f():
            boxes = [make()]
            boxes[0]['x'] = request.data
            os.system(boxes[0].get('x'))
        """,
    "an unknown method of request data": """
        def f():
            os.system(request.args.render())
        """,
    "json replaced through its __dict__": """
        json.__dict__['loads'] = lambda s: 'ls'

        def f():
            os.system(json.loads(request.data))
        """,
    "json replaced through globals()": """
        globals()['json'] = make()

        def f():
            os.system(json.loads(request.data))
        """,
    "a number next to a quoted part whose quoting breaks": """
        import shlex

        def f():
            safe = str(int(request.args['safe']))
            opaque = shlex.quote(build(request.args['opaque']))
            os.system('echo "' + safe + opaque + '"')
        """,
}


@pytest.mark.parametrize("body", ROUND2_ASSUMED.values(), ids=ROUND2_ASSUMED.keys())
def test_round2_assumed_flows_stay_candidates(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


ROUND2_ESTABLISHED = {
    "a default of request data's get": """
        def f():
            os.system(request.args.get('q', request.data))
        """,
    "a default of a dict's get": """
        def f():
            options = {'a': 'ls'}
            os.system(options.get('q', request.args['q']))
        """,
    "a container's own mutator": """
        def f():
            parts = []
            parts.append(request.args['q'])
            os.system(parts[0])
        """,
    "a request data method": """
        def f():
            os.system(request.get_json()['q'])
        """,
    "an accessor of request data": """
        def f():
            os.system(request.args.getlist('q')[0])
        """,
}


@pytest.mark.parametrize("body", ROUND2_ESTABLISHED.values(), ids=ROUND2_ESTABLISHED.keys())
def test_round2_established_flows_confirm(body):
    assert one(body).status is Status.CONFIRMED


def test_numeric_credit_survives_broken_quoting():
    # `safe` is a number: its credit does not rely on quoting; only `opaque`'s does
    f = one(
        """
        import shlex

        def f():
            safe = str(int(request.args['safe']))
            opaque = shlex.quote(request.args['opaque'])
            os.system('echo "' + safe + opaque + '"')
        """
    )
    assert f.status is Status.CONFIRMED


def test_a_callee_that_invalidates_credit_confirms(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def decode(n):\n    return n.to_bytes(8, 'big').decode()\n\n\n"
        "def view():\n    os.system(decode(int(request.data)))\n"
    )
    f = at(project(tmp_path, {"app.py": code}), "app.py", "os.system(decode(int(request.data)))")
    assert f.status is Status.CONFIRMED


def test_a_callee_that_breaks_quoting_confirms(tmp_path):
    code = (
        "from flask import request\nimport os, shlex\n\n\n"
        "def strip(s):\n    return s[1:]\n\n\n"
        "def view():\n    os.system('ls ' + strip(shlex.quote(request.data)))\n"
    )
    f = at(
        project(tmp_path, {"app.py": code}),
        "app.py",
        "os.system('ls ' + strip(shlex.quote(request.data)))",
    )
    assert f.status is Status.CONFIRMED


def test_credit_given_after_the_callee_still_counts(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def decode(n):\n    return n.to_bytes(8, 'big').decode()\n\n\n"
        "def view():\n    os.system(str(int(decode(int(request.data)))))\n"
    )
    f = at(
        project(tmp_path, {"app.py": code}),
        "app.py",
        "os.system(str(int(decode(int(request.data)))))",
    )
    assert f.status is not Status.CONFIRMED


def test_a_container_method_that_adds_nothing_is_assumed():
    f = one(
        """
        def f():
            parts = ['ls']
            parts.remove(request.args['q'])
            os.system(parts[0])
        """
    )
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_callee_that_re_encodes_a_quoted_value_confirms(tmp_path):
    code = (
        "from flask import request\nimport os, shlex\n\n\n"
        "def esc(s):\n    return 'ls ' + s.encode('unicode_escape').decode()\n\n\n"
        "def view():\n    os.system(esc(shlex.quote(request.data)))\n"
    )
    sink = "os.system(esc(shlex.quote(request.data)))"
    assert at(project(tmp_path, {"app.py": code}), "app.py", sink).status is Status.CONFIRMED


def test_quoting_done_by_a_callee_is_kept(tmp_path):
    # the caller's own (assumed) copy of the quoted argument does not decide what `q`
    # does with it: `q` quotes it again
    code = (
        "from flask import request\nimport os, shlex\n\n\n"
        "def q(s):\n    return shlex.quote(s)\n\n\n"
        "def view():\n    os.system('ls ' + q(shlex.quote(request.data)))\n"
    )
    sink = "os.system('ls ' + q(shlex.quote(request.data)))"
    assert at(project(tmp_path, {"app.py": code}), "app.py", sink).status is not Status.CONFIRMED


def test_a_callee_that_renders_a_quoted_value_in_a_list_confirms(tmp_path):
    # `str([q])` is `["'...'"]`: the quoted text ends up inside double quotes
    code = (
        "from flask import request\nimport os, shlex\n\n\n"
        "def show(s):\n    return 'ls ' + str([s])\n\n\n"
        "def view():\n    os.system(show(shlex.quote(request.data)))\n"
    )
    sink = "os.system(show(shlex.quote(request.data)))"
    assert at(project(tmp_path, {"app.py": code}), "app.py", sink).status is Status.CONFIRMED


# -- review round 3 --------------------------------------------------------------------------

ROUND3_ASSUMED = {
    "a template method of an object": """
        def f():
            os.system(make().format(request.data))
        """,
    "a string method of an object": """
        def f():
            os.system(make().replace('x', request.data))
        """,
    "a string method of a parameter": """
        def f(box):
            os.system(box.replace('x', request.data))
        """,
    "the index of insert": """
        def f():
            parts = ['ls']
            parts.insert(request.get_json()['pos'], 'pwd')
            os.system(parts[0])
        """,
}


@pytest.mark.parametrize("body", ROUND3_ASSUMED.values(), ids=ROUND3_ASSUMED.keys())
def test_round3_unestablished_flows_do_not_confirm(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


ROUND3_SANITIZED = {
    "url-decoding a number's text": """
        def f():
            os.system('ls ' + urllib.parse.unquote(str(int(request.data))))
        """,
    "joining a number's text into a path": """
        def f():
            os.system('ls ' + os.path.join('/tmp', str(int(request.data))))
        """,
    "json of a number's text": """
        def f():
            os.system('ls ' + str(json.loads(str(int(request.data)))))
        """,
}


@pytest.mark.parametrize("body", ROUND3_SANITIZED.values(), ids=ROUND3_SANITIZED.keys())
def test_a_number_s_text_keeps_its_credit_through_models(body):
    f = one(body)
    assert f.status is not Status.CONFIRMED
    assert f.suppression is None


ROUND3_ESTABLISHED = {
    "the value of insert": """
        def f():
            parts = ['ls']
            parts.insert(0, request.args['q'])
            os.system(parts[0])
        """,
    "a string method of request data": """
        def f():
            os.system(request.args['q'].replace('x', request.args['y']))
        """,
    "base64 of a number's text (any bytes)": """
        def f():
            os.system('ls ' + base64.b64decode(str(int(request.data))).decode())
        """,
    "a list after appending a constant": """
        def f():
            parts = ['ls']
            parts.append(' -l ')
            parts.append(request.data)
            os.system(' '.join(parts))
        """,
    "a dict after two item stores": """
        def f():
            options = {}
            options['a'] = 'ls'
            options['b'] = request.args['q']
            os.system(options['b'])
        """,
}


@pytest.mark.parametrize("body", ROUND3_ESTABLISHED.values(), ids=ROUND3_ESTABLISHED.keys())
def test_round3_established_flows_confirm(body):
    assert one(body).status is Status.CONFIRMED


def test_a_string_method_of_a_parameter_follows_the_caller(tmp_path):
    code = (
        "from flask import request\nimport os\n\n\n"
        "def run(cmd):\n    os.system(cmd.strip())\n\n\n"
        "def view():\n    run(request.data)\n"
    )
    assert at(project(tmp_path, {"app.py": code}), "app.py", "os.system(cmd.strip())").status is (
        Status.CONFIRMED
    )


def test_a_number_s_text_keeps_its_credit_in_a_linked_model(tmp_path):
    code = (
        "from flask import request\nimport os, urllib.parse\n\n\n"
        "def run(n):\n    os.system('ls ' + urllib.parse.unquote(n))\n\n\n"
        "def view():\n    run(str(int(request.data)))\n"
    )
    sink = "os.system('ls ' + urllib.parse.unquote(n))"
    assert at(project(tmp_path, {"app.py": code}), "app.py", sink).status is not Status.CONFIRMED


REPLACED = {
    "through globals()": {
        "app.py": (
            "from flask import request\nimport os\n\n\n"
            "def relay(x):\n    return x\n\n\n"
            "globals()['relay'] = lambda x: 'ls'\n\n\n"
            "def view():\n    os.system(relay(request.data))\n"
        ),
    },
    "an imported function, by its importer": {
        "helpers.py": "def ident(x):\n    return x\n",
        "app.py": (
            "from flask import request\nimport os\nimport helpers\n\n"
            "helpers.ident = lambda x: 'ls'\n\n\n"
            "def view():\n    os.system(helpers.ident(request.data))\n"
        ),
    },
    "an imported function, by a third module": {
        "helpers.py": "def ident(x):\n    return x\n",
        "patch.py": "import helpers\n\nhelpers.ident = lambda x: 'ls'\n",
        "app.py": (
            "from flask import request\nimport os\nimport helpers\n\n\n"
            "def view():\n    os.system(helpers.ident(request.data))\n"
        ),
    },
    "a computed setattr on the module": {
        "helpers.py": "def ident(x):\n    return x\n",
        "patch.py": "import helpers\n\nname = 'ident'\nsetattr(helpers, name, lambda x: 'ls')\n",
        "app.py": (
            "from flask import request\nimport os\nimport helpers\n\n\n"
            "def view():\n    os.system(helpers.ident(request.data))\n"
        ),
    },
}


@pytest.mark.parametrize("files", REPLACED.values(), ids=REPLACED.keys())
def test_a_replaceable_function_is_not_linked(tmp_path, files):
    (f,) = [f for f in project(tmp_path, files) if f.vuln_class == "cmdi"]
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


ONE_GUARD = {
    "the caller writes its namespace": {
        "helpers.py": "def ident(x):\n    return x\n",
        "app.py": (
            "from flask import request\nimport os\nfrom helpers import ident\n\n"
            "globals()['ident'] = lambda x: 'ls'\n\n\n"
            "def view():\n    os.system(ident(request.data))\n"
        ),
    },
    "the callee's module writes its namespace": {
        "helpers.py": "def ident(x):\n    return x\n\n\nglobals()['ident'] = lambda x: 'ls'\n",
        "app.py": (
            "from flask import request\nimport os\nfrom helpers import ident\n\n\n"
            "def view():\n    os.system(ident(request.data))\n"
        ),
    },
    "the caller rebinds the imported name": {
        "helpers.py": "def ident(x):\n    return x\n",
        "app.py": (
            "from flask import request\nimport os\nfrom helpers import ident\n\n"
            "if os.environ.get('X'):\n    ident = lambda x: 'ls'\n\n\n"
            "def view():\n    os.system(ident(request.data))\n"
        ),
    },
    "a constant setattr by a third module": {
        "helpers.py": "def ident(x):\n    return x\n",
        "patch.py": "import helpers\n\nsetattr(helpers, 'ident', lambda x: 'ls')\n",
        "app.py": (
            "from flask import request\nimport os\nimport helpers\n\n\n"
            "def view():\n    os.system(helpers.ident(request.data))\n"
        ),
    },
}


@pytest.mark.parametrize("files", ONE_GUARD.values(), ids=ONE_GUARD.keys())
def test_each_replacement_guard(tmp_path, files):
    (f,) = [f for f in project(tmp_path, files) if f.vuln_class == "cmdi"]
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_binary_decoder_drops_number_credit():
    f = one(
        """
        def f():
            subprocess.run(b'ls ' + base64.b64decode(str(int(request.data))), shell=True)
        """
    )
    assert f.status is Status.CONFIRMED


def test_a_change_through_a_possible_alias_is_assumed():
    f = one(
        """
        def f(c):
            parts = ['ls']
            other = [parts]  # holds `parts`; appending to `other` does not change it
            other.append(request.args['q'])
            os.system(parts[0])
        """
    )
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


NAMESPACE_WRITES = {
    "an alias of globals()": """
        g = globals()
        g['json'] = make()

        def f():
            os.system(json.loads(request.data))
        """,
    "a namespace's update": """
        json.__dict__.update(loads=lambda s: 'ls')

        def f():
            os.system(json.loads(request.data))
        """,
    "a builtin replaced through __builtins__": """
        __builtins__.compile = lambda *a: 'ls'

        def f():
            eval(compile(request.args['q'], '<q>', 'eval'))
        """,
}


@pytest.mark.parametrize("body", NAMESPACE_WRITES.values(), ids=NAMESPACE_WRITES.keys())
def test_namespace_writes_stop_models(body):
    code = HEADER + textwrap.dedent(body)
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith(("os.system(", "eval("))
    ]
    assert f.status is Status.CANDIDATE


NAMESPACE_READS = {
    "reading sys.modules": """
        main = sys.modules['__main__']
        path = getattr(main, '__file__', '')

        def f():
            os.system(json.loads(request.data))
        """,
    "a namespace given to exec": """
        def load(code, mod):
            exec(code, mod.__dict__)

        def f():
            os.system(json.loads(request.data))
        """,
}


@pytest.mark.parametrize("body", NAMESPACE_READS.values(), ids=NAMESPACE_READS.keys())
def test_namespace_reads_keep_models(body):
    code = HEADER + "import sys\n" + textwrap.dedent(body)
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("os.system")
    ]
    assert f.status is Status.CONFIRMED


def test_a_rebound_builtin_is_not_modelled():
    code = HEADER + (
        "if os.environ.get('X'):\n    compile = make()\n\n\n"
        "def f():\n    eval(compile(request.args['q'], '<q>', 'eval'))\n"
    )
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("eval(")
    ]
    assert f.status is Status.CANDIDATE


# -- review round 4: replacements from other scanned files ----------------------------------

APP_JSON = (
    "from flask import request\nimport json, os\n\n\n"
    "def view():\n    os.system(json.loads(request.data))\n"
)
PATCH_JSON = "import json\n\njson.loads = lambda s: 'ls'\n"


def by_sink(findings, vuln_class="cmdi"):
    return {(f.location.path, f.sink): f for f in findings if f.vuln_class == vuln_class}


def write(root, files):
    for name, code in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(code, encoding="utf-8")
    return scan(root, HackScanConfig(jobs=1)).findings


def test_a_library_model_replaced_by_another_file(tmp_path):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": PATCH_JSON})).values()
    assert f.status is Status.CANDIDATE
    assert f.suppression is None
    expected = "`json.loads`, which scanned code may replace (patch.py:3)"
    assert any(expected in n for n in notes(f)), notes(f)
    assert [e.message for e in f.evidence if e.kind == "taint_verdict"] == [ASSUMED_VERDICT]


def test_a_library_model_nobody_replaces_confirms(tmp_path):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "other.py": "import json\n"})).values()
    assert f.status is Status.CONFIRMED


def test_an_unaffected_path_keeps_the_confirmation(tmp_path):
    app = (
        "from flask import request\nimport json, os\n\n\n"
        "def view(c):\n"
        "    cmd = json.loads(request.data) if c else request.args['q']\n"
        "    os.system(cmd)\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": app, "patch.py": PATCH_JSON})).values()
    assert f.status is Status.CONFIRMED


def test_a_chain_of_models_depends_on_each(tmp_path):
    app = (
        "from flask import request\nimport html, os, urllib.parse\n\n\n"
        "def view():\n    os.system(html.unescape(urllib.parse.unquote(request.data)))\n"
    )
    patch = "import urllib.parse\n\nurllib.parse.unquote = lambda s: 'ls'\n"
    (f,) = by_sink(write(tmp_path, {"app.py": app, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_linked_flow_through_a_replaced_model(tmp_path):
    app = (
        "from flask import request\nimport json, os\n\n\n"
        "def run(s):\n    os.system(json.loads(s))\n\n\n"
        "def view():\n    run(request.data)\n"
    )
    (f,) = by_sink(write(tmp_path / "a", {"app.py": app, "patch.py": PATCH_JSON})).values()
    assert f.status is Status.CANDIDATE
    (g,) = by_sink(write(tmp_path / "b", {"app.py": app})).values()
    assert g.status is Status.CONFIRMED


IDENT = "def ident(x):\n    return x\n"
USE_RUN = (
    "from flask import request\nimport os\nfrom bridge import run\n\n\n"
    "def view():\n    os.system(run(request.data))\n"
)
USE_HELPERS = (
    "from flask import request\nimport os\nimport helpers\n\n\n"
    "def view():\n    os.system(helpers.ident(request.data))\n"
)
CROSS_FILE = {
    "a re-export replaced": {
        "helpers.py": IDENT,
        "bridge.py": "from helpers import ident as run\n",
        "patch.py": "import bridge\n\nbridge.run = lambda x: 'ls'\n",
        "app.py": USE_RUN,
    },
    "a computed setattr in a src layout": {
        "src/helpers.py": IDENT,
        "src/patch.py": (
            "import helpers\n\nname = 'ident'\nsetattr(helpers, name, lambda x: 'ls')\n"
        ),
        "src/app.py": USE_HELPERS,
    },
    "a foreign namespace write": {
        "helpers.py": IDENT,
        "patch.py": "import helpers\n\nhelpers.__dict__['ident'] = lambda x: 'ls'\n",
        "app.py": USE_HELPERS,
    },
    "a foreign namespace write with a computed key": {
        "helpers.py": IDENT,
        "patch.py": "import helpers\n\nname = 'ident'\nhelpers.__dict__[name] = lambda x: 'ls'\n",
        "app.py": USE_HELPERS,
    },
    "a foreign namespace written through an alias": {
        "helpers.py": IDENT,
        "patch.py": "import helpers\n\nns = helpers.__dict__\nns['ident'] = lambda x: 'ls'\n",
        "app.py": USE_HELPERS,
    },
    "a foreign namespace update": {
        "helpers.py": IDENT,
        "patch.py": "import helpers\n\nvars(helpers).update(ident=lambda x: 'ls')\n",
        "app.py": USE_HELPERS,
    },
}


@pytest.mark.parametrize("files", CROSS_FILE.values(), ids=CROSS_FILE.keys())
def test_a_function_replaced_from_another_file_is_not_linked(tmp_path, files):
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_the_same_projects_unpatched_confirm(tmp_path):
    for i, files in enumerate(CROSS_FILE.values()):
        clean = {k: v for k, v in files.items() if "patch" not in k}
        (f,) = by_sink(write(tmp_path / str(i), clean)).values()
        assert f.status is Status.CONFIRMED, i


def test_serial_and_parallel_scans_agree(tmp_path):
    write(
        tmp_path,
        {"app.py": APP_JSON, "patch.py": PATCH_JSON, "lib.py": USE_HELPERS, "helpers.py": IDENT},
    )
    one_job = scan(tmp_path, HackScanConfig(jobs=1)).findings
    two_jobs = scan(tmp_path, HackScanConfig(jobs=2)).findings
    assert [(f.id, f.status, f.confidence) for f in one_job] == [
        (f.id, f.status, f.confidence) for f in two_jobs
    ]


def test_the_index_of_setitem_is_assumed():
    f = one(
        """
        def f():
            parts = ['ls']
            parts.__setitem__(request.get_json()['pos'], 'pwd')
            os.system(parts[0])
        """
    )
    assert f.status is Status.CANDIDATE


def test_setdefault_returns_its_default():
    assert (
        one(
            """
        def f():
            os.system({}.setdefault('q', request.data))
        """
        ).status
        is Status.CONFIRMED
    )


ROUND4_WRITES = {
    "a getter alias": """
        from json import loads
        g = globals
        g()['loads'] = lambda s: 'ls'

        def f():
            os.system(loads(request.data))
        """,
    "a getter imported under another name": """
        from builtins import globals as g
        g()['json'] = make()

        def f():
            os.system(json.loads(request.data))
        """,
    "the __builtins__ mapping": """
        __builtins__['compile'] = lambda *a: 'ls'

        def f():
            eval(compile(request.args['q'], '<q>', 'eval'))
        """,
}


@pytest.mark.parametrize("body", ROUND4_WRITES.values(), ids=ROUND4_WRITES.keys())
def test_round4_namespace_writes_stop_models(body):
    code = HEADER + textwrap.dedent(body)
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith(("os.system(", "eval("))
    ]
    assert f.status is Status.CANDIDATE


def test_an_imported_eval_alias_is_not_a_namespace_write():
    code = HEADER + textwrap.dedent(
        """
        from builtins import eval as evaluate

        def f():
            os.system(json.loads(request.data))
        """
    )
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("os.system(")
    ]
    assert f.status is Status.CONFIRMED


def test_a_replaced_submodule_stops_its_models(tmp_path):
    app = (
        "from flask import request\nimport os\n\n\n"
        "def view():\n    os.system('ls ' + os.path.join('/tmp', request.data))\n"
    )
    patch = "import os\n\nos.path = object()\n"
    (f,) = by_sink(write(tmp_path, {"app.py": app, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_computed_setattr_on_a_parent_module_stops_its_submodule_models(tmp_path):
    app = (
        "from flask import request\nimport os\n\n\n"
        "def view():\n    os.system('ls ' + os.path.join('/tmp', request.data))\n"
    )
    patch = "import os\n\nname = 'path'\nsetattr(os, name, object())\n"
    (f,) = by_sink(write(tmp_path, {"app.py": app, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_direct_path_is_confirmed_here(tmp_path):
    app = (
        "from flask import request\nimport json, os\n\n\n"
        "def view(c):\n"
        "    cmd = json.loads(request.data) if c else request.args['q']\n"
        "    os.system(cmd)\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": app})).values()
    verdicts = [e.message for e in f.evidence if e.kind == "taint_verdict"]
    assert verdicts == [CONFIRMED_VERDICT], verdicts


def test_an_instance_attribute_does_not_replace_a_model(tmp_path):
    app = (
        "from flask import request\nimport os\n\n\n"
        "def view():\n    os.system('ls ' + os.path.join('/tmp', request.data))\n"
    )
    session = "class Store:\n    def __init__(self, path):\n        self.path = path\n"
    (f,) = by_sink(write(tmp_path, {"app.py": app, "session.py": session})).values()
    assert f.status is Status.CONFIRMED


# -- review round 5 --------------------------------------------------------------------------

APP_JOIN = (
    "from flask import request\nimport os\n\n\n"
    "def view():\n    os.system('ls ' + os.path.join('/tmp', request.data))\n"
)
APP_EVAL = (
    "from flask import request\n\n\n"
    "def view():\n    eval(compile(request.args['q'], '<q>', 'eval'))\n"
)
APP_STR = (
    "from flask import request\nimport os\n\n\ndef view():\n    os.system(str(request.data))\n"
)
ROUND5_REPLACED = {
    "os.path's namespace": (APP_JOIN, "import os\n\nos.path.__dict__['join'] = lambda *a: 'ls'\n"),
    "a computed setattr on os.path": (
        APP_JOIN,
        "import os\n\nname = 'join'\nsetattr(os.path, name, lambda *a: 'ls')\n",
    ),
    "the __builtins__ mapping": (APP_EVAL, "__builtins__['compile'] = lambda *a: 'ls'\n"),
    "a function-local import": (
        APP_JSON,
        "def patch():\n    import json\n    vars(json)['loads'] = lambda s: 'ls'\n",
    ),
    "a rebound self": (
        APP_JSON,
        "import json\n\n\nclass P:\n    def m(self):\n        self = json\n"
        "        self.loads = lambda s: 'ls'\n",
    ),
    "a builtin conversion": (APP_STR, "import builtins\n\nbuiltins.str = lambda x: 'ls'\n"),
}


@pytest.mark.parametrize("app, patch", ROUND5_REPLACED.values(), ids=ROUND5_REPLACED.keys())
def test_round5_replacements_from_another_file(tmp_path, app, patch):
    findings = write(tmp_path, {"app.py": app, "patch.py": patch})
    (f,) = [
        f for f in findings if f.location.path == "app.py" and f.sink.startswith(("os.", "eval("))
    ]
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


@pytest.mark.parametrize("app, patch", ROUND5_REPLACED.values(), ids=ROUND5_REPLACED.keys())
def test_round5_apps_unpatched_confirm(tmp_path, app, patch):
    findings = write(tmp_path, {"app.py": app})
    (f,) = [
        f for f in findings if f.location.path == "app.py" and f.sink.startswith(("os.", "eval("))
    ]
    assert f.status is Status.CONFIRMED


def test_a_replaced_sanitizer_does_not_establish_its_flow(tmp_path):
    app = (
        "from flask import request\nimport shlex, sqlite3\n\n\n"
        "def view():\n    sqlite3.connect('x').execute(shlex.quote(request.data))\n"
    )
    patch = "import shlex\n\nshlex.quote = lambda s: 'select 1'\n"
    (f,) = by_sink(write(tmp_path / "a", {"app.py": app, "patch.py": patch}), "sqli").values()
    assert f.status is Status.CANDIDATE
    (g,) = by_sink(write(tmp_path / "b", {"app.py": app}), "sqli").values()
    assert g.status is Status.CONFIRMED


def test_a_replaced_parent_module_is_not_linked(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/helpers.py": IDENT,
        "patch.py": "import pkg\n\npkg.helpers = object()\n",
        "app.py": (
            "from flask import request\nimport os\nimport pkg.helpers\n\n\n"
            "def view():\n    os.system(pkg.helpers.ident(request.data))\n"
        ),
    }
    (f,) = by_sink(write(tmp_path / "a", files)).values()
    assert f.status is Status.CANDIDATE
    del files["patch.py"]
    (g,) = by_sink(write(tmp_path / "b", files)).values()
    assert g.status is Status.CONFIRMED


def test_a_qualified_getter_alias_is_a_namespace_write():
    f = one(
        """
        import builtins
        g = builtins.globals
        g()['json'] = make()

        def f():
            os.system(json.loads(request.data))
        """
    )
    assert f.status is Status.CANDIDATE


ROUND5_OPTIONS = {
    "the characters strip removes": """
        def f():
            os.system('fixed'.strip(request.data))
        """,
    "the text replace looks for": """
        def f():
            os.system('fixed'.replace(request.data, ''))
        """,
    "a default after *args": """
        def f():
            os.system({}.get(*[], request.data))
        """,
}


@pytest.mark.parametrize("body", ROUND5_OPTIONS.values(), ids=ROUND5_OPTIONS.keys())
def test_round5_selecting_arguments_are_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_the_replacement_text_of_replace_is_data():
    assert (
        one(
            """
        def f():
            os.system('ls x'.replace('x', request.data))
        """
        ).status
        is Status.CONFIRMED
    )


# -- review round 6 --------------------------------------------------------------------------

ROUND6_JSON_PATCHES = {
    "builtins.vars": "import builtins, json\n\nbuiltins.vars(json)['loads'] = lambda s: 'ls'\n",
    "an imported vars alias": (
        "from builtins import vars as v\nimport json\n\nv(json)['loads'] = lambda s: 'ls'\n"
    ),
    "an imported setattr alias, computed name": (
        "from builtins import setattr as s\nimport json\n\nname = 'loads'\n"
        "s(json, name, lambda x: 'ls')\n"
    ),
    "builtins.setattr": (
        "import builtins, json\n\nbuiltins.setattr(json, 'loads', lambda s: 'ls')\n"
    ),
    "setattr as a value": (
        "import json\n\nwrite = setattr\nname = 'loads'\nwrite(json, name, lambda s: 'ls')\n"
    ),
    "a module alias": "import json\n\nm = json\nm.__dict__['loads'] = lambda s: 'ls'\n",
    "an augmented namespace update": (
        "import json\n\nns = json.__dict__\nns |= {'loads': lambda s: 'ls'}\n"
    ),
    "an assignment expression": (
        "import json\n\n(ns := json.__dict__)['loads'] = lambda s: 'ls'\n"
    ),
    "a module looked up in sys.modules": (
        "import sys\n\nsys.modules['json'].__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "a nonlocal self": (
        "import json\n\n\nclass P:\n    def m(self):\n        def inner():\n"
        "            nonlocal self\n            self = json\n\n        inner()\n"
        "        self.loads = lambda s: 'ls'\n"
    ),
    "a default that rebinds self": (
        "import json\n\n\nclass P:\n    def m(self):\n"
        "        def inner(a=(self := json)):\n            return a\n\n"
        "        self.loads = lambda s: 'ls'\n"
    ),
    "a qualified static method": (
        "import builtins, json\n\n\nclass P:\n    @builtins.staticmethod\n"
        "    def m(mod):\n        mod.loads = lambda s: 'ls'\n\n\nP.m(json)\n"
    ),
}


@pytest.mark.parametrize("patch", ROUND6_JSON_PATCHES.values(), ids=ROUND6_JSON_PATCHES.keys())
def test_round6_replacements_of_json_loads(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_nested_relative_import_replacement(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/helpers.py": IDENT,
        "pkg/patch.py": "def patch(key):\n    from . import helpers\n    vars(helpers)[key] = 1\n",
        "pkg/app.py": (
            "from flask import request\nimport os\nfrom pkg import helpers\n\n\n"
            "def view():\n    os.system(helpers.ident(request.data))\n"
        ),
    }
    (f,) = by_sink(write(tmp_path / "a", files)).values()
    assert f.status is Status.CANDIDATE
    del files["pkg/patch.py"]
    (g,) = by_sink(write(tmp_path / "b", files)).values()
    assert g.status is Status.CONFIRMED


def test_reading_a_module_does_not_replace_it(tmp_path):
    reader = (
        "import json, sys\n\nNAME = json.__name__\nLOADED = 'json' in sys.modules\n"
        "MAIN = sys.modules['__main__']\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "reader.py": reader})).values()
    assert f.status is Status.CONFIRMED


ROUND6_OPTIONS = {
    "the codec of str": """
        def f():
            os.system(str(b'fixed', request.args['codec']))
        """,
    "the codec of bytes": """
        def f():
            os.system(bytes('fixed', request.args['codec']))
        """,
    "an unused format argument": """
        def f():
            os.system('echo {0}'.format('fixed', request.data))
        """,
}


@pytest.mark.parametrize("body", ROUND6_OPTIONS.values(), ids=ROUND6_OPTIONS.keys())
def test_round6_option_arguments_are_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


ROUND6_ESTABLISHED = {
    "a used format argument": """
        def f():
            os.system('echo {1}'.format('fixed', request.data))
        """,
    "a named format field": """
        def f():
            os.system('echo {cmd}'.format(cmd=request.data, other='x'))
        """,
    "a qualified builtin conversion": """
        import builtins

        def f():
            os.system(builtins.str(request.data))
        """,
    "the data of str": """
        def f():
            os.system(str(request.data, 'utf-8'))
        """,
}


@pytest.mark.parametrize("body", ROUND6_ESTABLISHED.values(), ids=ROUND6_ESTABLISHED.keys())
def test_round6_established_flows_confirm(body):
    assert one(body).status is Status.CONFIRMED


PLUGIN_LOADER = (
    "import importlib\n\n\ndef load(name):\n    module = importlib.import_module(name)\n"
    "    module.setup()\n    return module\n"
)
UNKNOWN_MODULE_WRITES = {
    "a computed import's namespace": (
        "import importlib\n\n\ndef patch(name):\n"
        "    importlib.import_module(name).__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "a computed import set by name": (
        "import importlib\n\n\ndef patch(name, attr):\n"
        "    setattr(importlib.import_module(name), attr, lambda s: 'ls')\n"
    ),
    "a module put into sys.modules": (
        "import sys\n\n\ndef patch(name, fake):\n    sys.modules[name] = fake\n"
    ),
}


@pytest.mark.parametrize("patch", UNKNOWN_MODULE_WRITES.values(), ids=UNKNOWN_MODULE_WRITES.keys())
def test_writing_a_module_of_unknown_name_may_replace_any(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_plugin_loader_does_not_replace_modules(tmp_path):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "plugins.py": PLUGIN_LOADER})).values()
    assert f.status is Status.CONFIRMED
    files = {"helpers.py": IDENT, "plugins.py": PLUGIN_LOADER, "app.py": USE_HELPERS}
    (g,) = by_sink(write(tmp_path / "linked", files)).values()
    assert g.status is Status.CONFIRMED


# A module of computed name is not followed when handed on (the escape rule's boundary), so
# these reach each remaining guard alone.
COMPUTED_JSON = "importlib.import_module('j' + 'son')"
GUARDS_ALONE = {
    "an imported setattr alias": (
        "from builtins import setattr as s\nimport importlib\n\n"
        f"s({COMPUTED_JSON}, 'lo' + 'ads', lambda x: 'ls')\n"
    ),
    "a qualified setattr": (
        "import builtins, importlib\n\n"
        f"builtins.setattr({COMPUTED_JSON}, 'lo' + 'ads', lambda x: 'ls')\n"
    ),
    "setattr held in a name": (
        f"import importlib\n\nw = setattr\nw({COMPUTED_JSON}, 'lo' + 'ads', lambda x: 'ls')\n"
    ),
    "a rebound self": (
        "import importlib\n\n\nclass P:\n    def m(self):\n"
        f"        self = {COMPUTED_JSON}\n        self.loads = lambda s: 'ls'\n"
    ),
    "a qualified static method": (
        "import builtins, importlib\n\n\nclass P:\n    @builtins.staticmethod\n"
        f"    def m(mod):\n        mod.loads = lambda s: 'ls'\n\n\nP.m({COMPUTED_JSON})\n"
    ),
}


@pytest.mark.parametrize("patch", GUARDS_ALONE.values(), ids=GUARDS_ALONE.keys())
def test_each_replacement_guard_alone(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_submodule_replaced_through_a_computed_import(tmp_path):
    patch = "import importlib\n\nimportlib.import_module('o' + 's').path = object()\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JOIN, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_parent_module_attribute_set_by_name(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/helpers.py": IDENT,
        "patch.py": "import pkg\n\nsetattr(pkg, 'helpers', object())\n",
        "app.py": (
            "from flask import request\nimport os\nimport pkg.helpers\n\n\n"
            "def view():\n    os.system(pkg.helpers.ident(request.data))\n"
        ),
    }
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CANDIDATE


def test_an_alias_of_sys_modules_may_replace_any_module(tmp_path):
    patch = "import sys\n\nmods = sys.modules\nmods['json'] = object()\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


# -- review round 7 --------------------------------------------------------------------------

ROUND7_OPTIONS = {
    "the codec of builtins.str": """
        import builtins

        def f():
            os.system(builtins.str(b'fixed', request.data))
        """,
    "the codec of builtins.bytes": """
        import builtins

        def f():
            os.system(builtins.bytes('fixed', request.args['codec']))
        """,
    "the key of builtins.sorted": """
        import builtins

        def f():
            os.system(' '.join(builtins.sorted(['ls'], key=request.data)))
        """,
    "an unused argument with a conversion": """
        def f():
            os.system('{0!s}'.format('fixed', request.data))
        """,
    "an unused argument with a spec": """
        def f():
            os.system('{0:>5}'.format('fixed', request.data))
        """,
}


@pytest.mark.parametrize("body", ROUND7_OPTIONS.values(), ids=ROUND7_OPTIONS.keys())
def test_round7_option_arguments_are_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_field_nested_in_a_spec_is_used():
    f = one(
        """
        def f():
            os.system('ls {0:{1}}'.format('x', request.data))
        """
    )
    assert f.status is not Status.SUPPRESSED


ROUND7_PATCHES = {
    "a function's globals": "import json\n\njson.loads.__globals__['loads'] = lambda s: 'ls'\n",
    "an imported function's globals": (
        "from json import loads\n\nloads.__globals__['loads'] = lambda s: 'ls'\n"
    ),
    "globals of unknown origin": ("def patch(fn):\n    fn.__globals__['loads'] = lambda s: 'ls'\n"),
    "an import binding self": (
        "class P:\n    def m(self):\n        import json as self\n"
        "        self.loads = lambda s: 'ls'\n"
    ),
}


@pytest.mark.parametrize("patch", ROUND7_PATCHES.values(), ids=ROUND7_PATCHES.keys())
def test_round7_replacements_of_json_loads(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


PKG_APP = (
    "from flask import request\nimport os\nimport pkg.helpers\n\n\n"
    "def view():\n    os.system(pkg.helpers.ident(request.data))\n"
)
ROUND7_PKG = {
    "a replaced parent package": "import pkg\n\nvars(pkg)['helpers'] = object()\n",
    "a relative literal import": (
        "import importlib\n\n"
        "importlib.import_module('.helpers', 'pkg').__dict__['ident'] = lambda x: 'ls'\n"
    ),
}


@pytest.mark.parametrize("patch", ROUND7_PKG.values(), ids=ROUND7_PKG.keys())
def test_round7_package_replacements(tmp_path, patch):
    files = {"pkg/__init__.py": "", "pkg/helpers.py": IDENT, "patch.py": patch, "app.py": PKG_APP}
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CANDIDATE


def test_round7_package_unpatched_confirms(tmp_path):
    files = {"pkg/__init__.py": "", "pkg/helpers.py": IDENT, "app.py": PKG_APP}
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CONFIRMED


def test_a_namespace_package_member_replaced_by_name(tmp_path):
    # no `pkg/__init__.py`: no file for the parent, so only the name on the way stops the link
    files = {
        "pkg/helpers.py": IDENT,
        "patch.py": "import importlib\n\nimportlib.import_module('p' + 'kg').helpers = object()\n",
        "app.py": PKG_APP,
    }
    (f,) = by_sink(write(tmp_path / "a", files)).values()
    assert f.status is Status.CANDIDATE
    del files["patch.py"]
    (g,) = by_sink(write(tmp_path / "b", files)).values()
    assert g.status is Status.CONFIRMED


def test_a_constant_setattr_on_an_object_handed_in(tmp_path):
    patch = (
        "import importlib\n\n\ndef patch(mod):\n    setattr(mod, 'loads', lambda s: 'ls')\n\n\n"
        "patch(importlib.import_module('j' + 'son'))\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_field_nested_in_a_spec_is_data():
    f = one(
        """
        def f():
            os.system('ls {0:{1}}'.format('x', request.data))
        """
    )
    assert f.status is Status.CONFIRMED


# -- review round 8 --------------------------------------------------------------------------


def test_globals_of_a_re_exported_function(tmp_path):
    files = {
        "helpers.py": IDENT,
        "bridge.py": "from helpers import ident\n",
        "patch.py": "from bridge import ident\n\nident.__globals__['ident'] = lambda x: 'ls'\n",
        "app.py": USE_HELPERS,
    }
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CANDIDATE


def test_a_dotted_dunder_import_returns_the_top_package(tmp_path):
    patch = "__import__('json.decoder').__dict__['loads'] = lambda s: 'ls'\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_dunder_import_with_a_fromlist_returns_the_submodule(tmp_path):
    patch = "__import__('json.decoder', None, None, ['x']).__dict__['y'] = 1\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CONFIRMED  # json.decoder, not json, is written


def test_a_scanned_module_shadows_the_library(tmp_path):
    shadow = "def loads(s):\n    return 'ls'\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "json.py": shadow})).values()
    assert f.status is Status.CANDIDATE
    assert any("json.py" in n for n in notes(f)), notes(f)


def test_a_module_inside_a_package_does_not_shadow(tmp_path):
    files = {
        "app.py": APP_JSON,
        "util/__init__.py": "",
        "util/json.py": "def loads(s):\n    return 1\n",
    }
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CONFIRMED


def test_globals_of_a_resolved_function_stop_only_its_module(tmp_path):
    files = {
        "helpers.py": IDENT,
        "other.py": "def other(x):\n    return x\n",
        "bridge.py": "from helpers import ident\n",
        "patch.py": "from bridge import ident\n\nident.__globals__['ident'] = lambda x: 'ls'\n",
        "app.py": USE_HELPERS,
        "app2.py": (
            "from flask import request\nimport os\nimport other\n\n\n"
            "def view():\n    os.system(other.other(request.data))\n"
        ),
    }
    found = by_sink(write(tmp_path, files))
    assert found[("app.py", "os.system(helpers.ident(request.data))")].status is Status.CANDIDATE
    assert found[("app2.py", "os.system(other.other(request.data))")].status is Status.CONFIRMED


def test_globals_of_an_unresolved_scanned_name_may_be_any_module(tmp_path):
    files = {
        "helpers.py": IDENT,
        "bridge.py": "X = 1\n",
        "patch.py": "from bridge import missing\n\nmissing.__globals__['ident'] = lambda x: 'ls'\n",
        "app.py": USE_HELPERS,
    }
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CANDIDATE


# -- review round 9 --------------------------------------------------------------------------


def test_a_packaged_namesake_does_not_hide_a_library_replacement(tmp_path):
    files = {
        "app.py": APP_JSON,
        "util/__init__.py": "",
        "util/json.py": "X = 1\n",
        "patch.py": "import json\n\njson.__dict__['loads'] = lambda s: 'ls'\n",
    }
    found = by_sink(write(tmp_path, files))
    assert found[("app.py", "os.system(json.loads(request.data))")].status is Status.CANDIDATE


CALLER_BINDING = {
    "the caller's binding set from outside": (
        "import types\nimport app\n\napp.json = types.SimpleNamespace(loads=lambda s: 'ls')\n"
    ),
    "the caller's namespace written from outside": (
        "import types\nimport app\n\napp.__dict__['json'] = types.SimpleNamespace(loads=len)\n"
    ),
}


@pytest.mark.parametrize("patch", CALLER_BINDING.values(), ids=CALLER_BINDING.keys())
def test_the_binding_a_model_is_reached_through(tmp_path, patch):
    found = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch}))
    assert found[("app.py", "os.system(json.loads(request.data))")].status is Status.CANDIDATE


def test_another_module_s_binding_does_not_matter(tmp_path):
    patch = "import types\nimport other\n\nother.json = types.SimpleNamespace(loads=len)\n"
    files = {"app.py": APP_JSON, "other.py": "import json\n", "patch.py": patch}
    found = by_sink(write(tmp_path, files))
    assert found[("app.py", "os.system(json.loads(request.data))")].status is Status.CONFIRMED


SHADOW_PARENTS = {
    "urllib.py": "class parse:\n    @staticmethod\n    def unquote(s):\n        return 'ls'\n",
    "urllib/__init__.py": "X = 1\n",
}


@pytest.mark.parametrize("name, code", SHADOW_PARENTS.items(), ids=SHADOW_PARENTS.keys())
def test_a_shadowed_parent_module(tmp_path, name, code):
    app = (
        "from flask import request\nimport os\nfrom urllib import parse\n\n\n"
        "def view():\n    os.system(parse.unquote(request.data))\n"
    )
    found = by_sink(write(tmp_path, {"app.py": app, name: code}))
    assert found[("app.py", "os.system(parse.unquote(request.data))")].status is Status.CANDIDATE


ROUND9_LOCAL = {
    "a rebound builtin str": """
        from builtins import str
        str = lambda x: 'ls'

        def f():
            os.system(str(request.data))
        """,
    "str through globals()": """
        globals()['str'] = lambda x: 'ls'

        def f():
            os.system(str(request.data))
        """,
    "unpacked format arguments": """
        def f():
            os.system('fixed'.format(*[request.data]))
        """,
    "unpacked format keywords": """
        def f():
            os.system('fixed'.format(**{'unused': request.data}))
        """,
    "format_map without fields": """
        def f():
            os.system('fixed'.format_map({'unused': request.data}))
        """,
}


@pytest.mark.parametrize("body", ROUND9_LOCAL.values(), ids=ROUND9_LOCAL.keys())
def test_round9_unestablished_flows(body):
    code = HEADER + textwrap.dedent(body)
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("os.system(")
    ]
    assert f.status is Status.CANDIDATE


def test_format_map_with_a_field_keeps_the_mapping():
    assert (
        one(
            """
        def f():
            os.system('ls {cmd}'.format_map({'cmd': request.data}))
        """
        ).status
        is Status.CONFIRMED
    )


# -- review round 10 -------------------------------------------------------------------------

APP_GO = (
    "from flask import request\nimport os\nfrom helpers import ident as go\n\n\n"
    "def view():\n    os.system(go(request.data))\n"
)
LINKED_BINDING = {
    "the caller's binding set from outside": "import app\n\napp.go = lambda x: 'ls'\n",
    "the caller's namespace written from outside": "import app\n\napp.__dict__['go'] = len\n",
}


@pytest.mark.parametrize("patch", LINKED_BINDING.values(), ids=LINKED_BINDING.keys())
def test_a_linked_call_through_a_replaced_binding(tmp_path, patch):
    files = {"helpers.py": IDENT, "app.py": APP_GO, "patch.py": patch}
    found = by_sink(write(tmp_path, files))
    assert found[("app.py", "os.system(go(request.data))")].status is Status.CANDIDATE


def test_a_linked_call_through_an_unreplaced_binding(tmp_path):
    files = {"helpers.py": IDENT, "app.py": APP_GO}
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CONFIRMED


MODULE_LOOKUP_PATCHES = {
    "sys.modules.get": "import sys\n\nsys.modules.get('json').__dict__['loads'] = lambda s: 'ls'\n",
    "sys.modules.__getitem__": (
        "import sys\n\nsys.modules.__getitem__('json').__dict__['loads'] = lambda s: 'ls'\n"
    ),
}


@pytest.mark.parametrize("patch", MODULE_LOOKUP_PATCHES.values(), ids=MODULE_LOOKUP_PATCHES.keys())
def test_a_module_looked_up_through_a_mapping_method(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


PRINTF_UNUSED = {
    "a template without conversions": """
        def f():
            os.system('fixed' % {'unused': request.data})
        """,
    "an unused mapping key": """
        def f():
            os.system('ls %(a)s' % {'a': 'x', 'unused': request.data})
        """,
}


@pytest.mark.parametrize("body", PRINTF_UNUSED.values(), ids=PRINTF_UNUSED.keys())
def test_unused_printf_data_is_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_used_printf_mapping_key_is_data():
    assert (
        one(
            """
        def f():
            os.system('ls %(a)s' % {'a': request.data})
        """
        ).status
        is Status.CONFIRMED
    )


# -- review round 11 -------------------------------------------------------------------------

NAMESPACE_LOOKUPS = {
    "globals()[name]": "import json\n\nglobals()['json'].__dict__['loads'] = lambda s: 'ls'\n",
    "globals().get(name)": (
        "import json\n\nglobals().get('json').__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "globals()[computed]": (
        "import json\n\nname = 'js' + 'on'\nglobals()[name].__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "vars()[name]": "import json\n\nvars()['json'].__dict__['loads'] = lambda s: 'ls'\n",
}


@pytest.mark.parametrize("patch", NAMESPACE_LOOKUPS.values(), ids=NAMESPACE_LOOKUPS.keys())
def test_a_module_looked_up_in_a_namespace(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


@pytest.mark.parametrize("patch", NAMESPACE_LOOKUPS.values(), ids=NAMESPACE_LOOKUPS.keys())
def test_a_module_looked_up_in_its_own_namespace(patch):
    code = HEADER + patch + "\n\ndef f():\n    os.system(json.loads(request.data))\n"
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("os.system(")
    ]
    assert f.status is Status.CANDIDATE


ROUND11_UNUSED = {
    "an unused format_map entry": """
        def f():
            os.system('ls {a}'.format_map({'a': 'fixed', 'unused': request.data}))
        """,
    "an overwritten printf entry": """
        def f():
            os.system('ls %(a)s' % {'a': request.data, 'a': 'fixed'})
        """,
    "an overwritten format_map entry": """
        def f():
            os.system('ls {a}'.format_map({'a': request.data, 'a': 'fixed'}))
        """,
}


@pytest.mark.parametrize("body", ROUND11_UNUSED.values(), ids=ROUND11_UNUSED.keys())
def test_round11_unused_entries_are_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


ROUND11_USED = {
    "a printf key with parentheses": """
        def f():
            os.system('ls %(a(b))s' % {'a(b)': request.data})
        """,
    "the last value of a printf key": """
        def f():
            os.system('ls %(a)s' % {'a': 'fixed', 'a': request.data})
        """,
}


@pytest.mark.parametrize("body", ROUND11_USED.values(), ids=ROUND11_USED.keys())
def test_round11_used_entries_confirm(body):
    assert one(body).status is Status.CONFIRMED


# -- review round 12 -------------------------------------------------------------------------


def test_a_getter_alias_lookup_from_another_file(tmp_path):
    patch = "import json\n\ng = globals\ng()['json'].__dict__['loads'] = lambda s: 'ls'\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


APP_PARSE = (
    "from flask import request\nimport os\nimport urllib.parse\n\n\n"
    "def view():\n    os.system(urllib.parse.unquote(request.data))\n"
)
UNKNOWN_THROUGH_ATTRIBUTES = {
    "import_module": (
        "import importlib\n\n\ndef patch(name):\n"
        "    importlib.import_module(name).parse.__dict__['unquote'] = lambda s: 'ls'\n"
    ),
    "sys.modules": (
        "import sys\n\n\ndef patch(name):\n"
        "    sys.modules[name].parse.__dict__['unquote'] = lambda s: 'ls'\n"
    ),
}


@pytest.mark.parametrize(
    "patch", UNKNOWN_THROUGH_ATTRIBUTES.values(), ids=UNKNOWN_THROUGH_ATTRIBUTES.keys()
)
def test_an_unknown_module_stays_unknown_through_attributes(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_PARSE, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


ROUND12_UNUSED = {
    "a format_map entry with a number key": """
        def f():
            os.system('ls {a}'.format_map({'a': 'fixed', 0: request.data}))
        """,
    "a printf entry with a number key": """
        def f():
            os.system('ls %(a)s' % {'a': 'fixed', 0: request.data})
        """,
}


@pytest.mark.parametrize("body", ROUND12_UNUSED.values(), ids=ROUND12_UNUSED.keys())
def test_round12_unused_entries_are_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE


ROUND12_KEYWORDS = {
    "str(object=...)": """
        def f():
            os.system(str(object=request.args['q']))
        """,
    "bytes(source=...)": """
        def f():
            os.system(bytes(source=request.args['q'], encoding='utf8').decode())
        """,
}


@pytest.mark.parametrize("body", ROUND12_KEYWORDS.values(), ids=ROUND12_KEYWORDS.keys())
def test_round12_builtin_keyword_data_confirms(body):
    assert one(body).status is Status.CONFIRMED


def test_the_encoding_keyword_of_bytes_is_not_data():
    f = one(
        """
        def f():
            os.system(bytes(source='ls', encoding=request.args['codec']).decode())
        """
    )
    assert f.status is Status.CANDIDATE


def test_a_write_helper_kept_in_a_container(tmp_path):
    # not a name bound to the helper (`ops[0](...)`): any module may be written
    patch = (
        "import importlib\n\nops = [setattr]\n"
        "ops[0](importlib.import_module('j' + 'son'), 'lo' + 'ads', lambda s: 'ls')\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_namespace_getter_kept_in_a_container():
    code = HEADER + (
        "gs = [globals]\ngs[0]()['json'] = make()\n\n\n"
        "def f():\n    os.system(json.loads(request.data))\n"
    )
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("os.system(")
    ]
    assert f.status is Status.CANDIDATE


# -- review round 13 -------------------------------------------------------------------------

ESCAPED_HELPERS = {
    "a namespace getter kept in a list": (
        "import json\n\nops = [globals]\nops[0]()['json'].__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "an import helper kept in a list": (
        "import importlib\n\nops = [importlib.import_module]\n"
        "ops[0]('json').__dict__['loads'] = lambda s: 'ls'\n"
    ),
}


@pytest.mark.parametrize("patch", ESCAPED_HELPERS.values(), ids=ESCAPED_HELPERS.keys())
def test_an_escaped_helper_from_another_file(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_an_aliased_import_helper_is_followed_not_escaped(tmp_path):
    # `imp = importlib.import_module` is followed: only what it imports and writes counts
    plugins = (
        "import importlib\n\nimp = importlib.import_module\nmod = imp('plugins_x')\nmod.setup()\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "plugins.py": plugins})).values()
    assert f.status is Status.CONFIRMED


ROUND13_UNUSED = {
    "a bytes printf entry": """
        def f():
            os.system((b'%(safe)s' % {b'safe': b'fixed', b'unused': request.data}).decode())
        """,
    "a superscript field name": """
        def f():
            os.system('{²}'.format_map({'²': 'fixed', 'unused': request.data}))
        """,
}


@pytest.mark.parametrize("body", ROUND13_UNUSED.values(), ids=ROUND13_UNUSED.keys())
def test_round13_unused_entries_are_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE


def test_a_used_bytes_printf_entry_is_data():
    assert (
        one(
            """
        def f():
            os.system((b'ls %(cmd)s' % {b'cmd': request.data}).decode())
        """
        ).status
        is Status.CONFIRMED
    )


def test_an_escaped_getter_may_rebind_an_imported_function():
    code = (  # (no `import json`: only this module's own name `loads` is rebound)
        "from flask import request\nimport os\nfrom json import loads\n"
        "gs = [globals]\ngs[0]()['loads'] = make()\n\n\n"
        "def f():\n    os.system(loads(request.data))\n"
    )
    (f,) = [
        f
        for f in analyze_source(code, "app.py", builtin_plugins()).findings
        if f.sink.startswith("os.system(")
    ]
    assert f.status is Status.CANDIDATE


# -- review round 14 -------------------------------------------------------------------------

NAMESPACE_COPIES = {
    "globals().copy()": (
        "import json\n\nglobals().copy()['json'].__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "sys.modules.copy()": (
        "import sys\n\nsys.modules.copy()['json'].__dict__['loads'] = lambda s: 'ls'\n"
    ),
    "globals().values()": (
        "import json\n\nfor m in globals().values():\n    m.__dict__['loads'] = lambda s: 'ls'\n"
    ),
}


@pytest.mark.parametrize("patch", NAMESPACE_COPIES.values(), ids=NAMESPACE_COPIES.keys())
def test_a_copied_namespace_keeps_its_modules(tmp_path, patch):
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


CODE_REPLACED = {
    "a linked function's code": (
        "from helpers import ident\n\n\ndef fixed(x):\n    return 'ls'\n\n\n"
        "ident.__code__ = fixed.__code__\n"
    ),
    "a linked function's code by setattr": (
        "import helpers\n\n\ndef fixed(x):\n    return 'ls'\n\n\n"
        "setattr(helpers.ident, '__code__', fixed.__code__)\n"
    ),
    "a function of unknown origin": (
        "def fixed(x):\n    return 'ls'\n\n\ndef patch(fn):\n    fn.__code__ = fixed.__code__\n"
    ),
}


@pytest.mark.parametrize("patch", CODE_REPLACED.values(), ids=CODE_REPLACED.keys())
def test_a_function_whose_code_is_replaced_is_not_linked(tmp_path, patch):
    files = {"helpers.py": IDENT, "app.py": USE_HELPERS, "patch.py": patch}
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CANDIDATE
    assert f.suppression is None


def test_a_library_function_whose_code_is_replaced(tmp_path):
    patch = "import json\n\n\ndef fixed(s):\n    return 'ls'\n\n\n"
    patch += "json.loads.__code__ = fixed.__code__\n"
    (f,) = by_sink(write(tmp_path, {"app.py": APP_JSON, "patch.py": patch})).values()
    assert f.status is Status.CANDIDATE


def test_a_documentation_attribute_does_not_replace(tmp_path):
    patch = "from helpers import ident\n\nident.__doc__ = 'the identity'\n"
    files = {"helpers.py": IDENT, "app.py": USE_HELPERS, "patch.py": patch}
    (f,) = by_sink(write(tmp_path, files)).values()
    assert f.status is Status.CONFIRMED


# -- the confirmation contract (E-scope-2) ---------------------------------------------------

CONTRACT_ESTABLISHED = {
    "standard input read": """
        import sys

        def f():
            os.system(sys.stdin.read())
        """,
    "a request stream read": """
        def f():
            os.system(request.stream.read().decode())
        """,
    "an uploaded file read": """
        def f():
            os.system(request.files['upload'].read().decode())
        """,
    "a setdefault key": """
        def f():
            d = {}
            d.setdefault(request.args['q'], 'fixed')
            os.system(str(d))
        """,
    "the list __iadd__ returns": """
        def f():
            parts = ['ls']
            os.system(' '.join(parts.__iadd__([request.args['q']])))
        """,
}


@pytest.mark.parametrize("body", CONTRACT_ESTABLISHED.values(), ids=CONTRACT_ESTABLISHED.keys())
def test_contract_supported_confirmations(body):
    assert one(body).status is Status.CONFIRMED


def test_a_file_opened_from_a_tainted_name_is_not_its_content():
    f = one(
        """
        def f():
            os.system(open(request.args['name']).read())
        """
    )
    assert f.status is Status.CANDIDATE


CUSTOM_RESULTS = {
    "a custom JSON decoder": """
        def f():
            os.system(json.loads(request.data, cls=make()))
        """,
    "a JSON object hook": """
        def f():
            os.system(json.loads(request.data, object_hook=make()))
        """,
    "a replacement function": """
        def f():
            os.system(re.sub('.*', make(), request.args['q']))
        """,
}


@pytest.mark.parametrize("body", CUSTOM_RESULTS.values(), ids=CUSTOM_RESULTS.keys())
def test_a_call_configured_to_replace_its_result_is_assumed(body):
    f = one(body)
    assert f.status is Status.CANDIDATE
    assert f.suppression is None
    assert any(e.message == ASSUMED_VERDICT for e in f.evidence)


QUOTED_PROGRAM = """
from flask import request
import os, shlex


def view():
    os.system(shlex.quote(request.data))


def shell():
    os.system('sh -c ' + shlex.quote(request.data))
"""


def test_the_decided_flow_is_the_exported_flow(tmp_path):
    # the quoted value is the program (or `sh -c` runs it): no quoting credit, with or
    # without whole-scan linking
    local = [
        f.status
        for f in analyze_source(QUOTED_PROGRAM, "app.py", builtin_plugins()).findings
        if f.vuln_class == "cmdi"
    ]
    linked = [
        f.status for f in project(tmp_path, {"app.py": QUOTED_PROGRAM}) if f.vuln_class == "cmdi"
    ]
    assert local == linked == [Status.CONFIRMED, Status.CONFIRMED]


HARMLESS = {
    "a module's documentation": "import json\n\njson.__doc__ = 'documentation'\n",
    "reading a function's globals": (
        "import helpers\n\nNAMES = list(helpers.ident.__globals__.keys())\n"
    ),
}


@pytest.mark.parametrize("patch", HARMLESS.values(), ids=HARMLESS.keys())
def test_metadata_and_reads_do_not_replace(tmp_path, patch):
    files = {"helpers.py": IDENT, "app.py": APP_JSON, "app2.py": USE_HELPERS, "patch.py": patch}
    assert {f.status for f in by_sink(write(tmp_path, files)).values()} == {Status.CONFIRMED}


def test_outputs_carry_the_contract(tmp_path):
    from hackscan.cli import _json
    from hackscan.core.models import CONFIRMATION_CONTRACT
    from hackscan.sarif.generator import export_sarif

    (tmp_path / "app.py").write_text(
        APP_JSON + "\n\ndef other():\n    os.system(make(request.data))\n"
    )
    result = scan(tmp_path, HackScanConfig(jobs=1))
    data = _json(result, result.findings)
    assert data["tool"]["confirmation_contract"] == CONFIRMATION_CONTRACT
    bases = {f["sink"]: f["confirmation_basis"] for f in data["findings"]}
    assert bases["os.system(json.loads(request.data))"] == "modelled-flow"
    assert bases["os.system(make(request.data))"] == "assumed-flow"
    sarif = export_sarif(result)
    results = sarif["runs"][0]["results"]
    confirmed = [r for r in results if r["properties"]["status"] == "confirmed"]
    assert confirmed and all(CONFIRMED_VERDICT in r["message"]["text"] for r in confirmed)
    assert all(r["properties"]["confirmationContract"] == CONFIRMATION_CONTRACT for r in results)


def test_a_noted_input_object_read_is_assumed(tmp_path):
    # a project note may name any object as input: its `read` is not an input stream's
    (tmp_path / "app.py").write_text(
        "import os\nfrom myframework import incoming\n\nos.system(incoming.read())\n",
        encoding="utf-8",
    )
    note = "knowledge:\n  - type: source_name\n    value: myframework.incoming\n"
    (tmp_path / ".hackscan.yml").write_text(note + "    rationale: r\n    evidence: e\n")
    (f,) = [f for f in scan(tmp_path, load(tmp_path)).findings if f.vuln_class == "cmdi"]
    assert f.status is Status.CANDIDATE


MODEL_KEYWORDS = {
    "a non-data keyword": """
        def f():
            os.system(urllib.parse.unquote('ls', encoding=request.args['e']))
        """,
}


@pytest.mark.parametrize("body", MODEL_KEYWORDS.values(), ids=MODEL_KEYWORDS.keys())
def test_a_model_s_option_keyword_is_assumed(body):
    assert one(body).status is Status.CANDIDATE


def test_every_positional_of_an_all_positional_model_is_data():
    assert (
        one(
            """
        def f(parts):
            os.system('ls ' + os.path.join(*parts, request.args['q']))
        """
        ).status
        is Status.CONFIRMED
    )


# -- final contract review -----------------------------------------------------------------


def test_a_replaced_model_path_is_not_shown_as_established(tmp_path):
    app = (
        "from flask import request\nimport json, os\n\n\n"
        "def view():\n    os.system(request.args['q'] + json.loads(request.data))\n"
    )
    (f,) = by_sink(write(tmp_path, {"app.py": app, "patch.py": PATCH_JSON})).values()
    assert f.status is Status.CONFIRMED  # the direct source
    steps = [e.message for e in f.evidence if e.kind == "taint_step"]
    assert steps == ["Modelled flow: untrusted Flask request data (request.args) at line 6."], steps


CODEX_DISTINGUISHERS = {
    "a data argument unpacked from *args": """
        def f():
            os.system(urllib.parse.unquote(*[request.data]))
        """,
    "a stream that may be another object": """
        def f(flag, other):
            stream = request.stream if flag else other
            os.system(stream.read())
        """,
}


@pytest.mark.parametrize("body", CODEX_DISTINGUISHERS.values(), ids=CODEX_DISTINGUISHERS.keys())
def test_codex_distinguishers(body):
    assert one(body).status is Status.CANDIDATE
