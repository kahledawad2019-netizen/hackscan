from __future__ import annotations

import textwrap

import pytest

from vulnhawk.analyzers.ast_pass import analyze_source
from vulnhawk.analyzers.suppressions import INLINE
from vulnhawk.analyzers.taint_pass import CONSTANT_INPUT, SANITIZED
from vulnhawk.core.models import Status
from vulnhawk.plugins.loader import builtin_plugins

HEADER = "import os\nimport sys\nimport shlex\nimport subprocess\n"


def scan(code: str, *, taint: bool = True):
    source = HEADER + textwrap.dedent(code)
    result = analyze_source(source, "t.py", builtin_plugins(), taint=taint)
    assert not result.errors, result.errors
    return result.findings


def verdict(code: str) -> tuple[Status, str | None]:
    (f,) = scan(code)
    return f.status, f.suppression


def test_constant_flows_are_suppressed():
    assert verdict(
        """
        def f():
            cmd = "ls -la"
            os.system(cmd)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


def test_parameters_stay_candidates():
    assert verdict(
        """
        def f(cmd):
            os.system(cmd)
        """
    ) == (Status.CANDIDATE, None)


def test_source_confirms_with_trace_and_boost():
    (f,) = scan(
        """
        def f():
            os.system(input())
        """
    )
    assert f.status is Status.CONFIRMED
    assert f.confidence == min(100, 50 + 35)
    assert any("input()" in e.message for e in f.evidence if e.producer == "taint")


def test_branch_join_keeps_taint():
    assert (
        verdict(
            """
        def f(flag):
            cmd = "ls"
            if flag:
                cmd = sys.argv[1]
            os.system(cmd)
        """
        )[0]
        is Status.CONFIRMED
    )


def test_both_branches_constant_is_suppressed():
    assert verdict(
        """
        def f(flag):
            if flag:
                cmd = "ls"
            else:
                cmd = "pwd"
            os.system(cmd)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


def test_returning_branch_does_not_reach_sink():
    assert verdict(
        """
        def f(flag):
            cmd = "ls"
            if flag:
                cmd = input()
                return
            os.system(cmd)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


def test_loop_carried_taint_reaches_fixpoint():
    assert (
        verdict(
            """
        def f(items):
            cmd = "ls"
            for _ in items:
                os.system(cmd)
                cmd = input()
        """
        )[0]
        is Status.CONFIRMED
    )


def test_while_loop_and_try_except():
    assert (
        verdict(
            """
        def f():
            cmd = "ls"
            while True:
                try:
                    cmd = input()
                except ValueError:
                    break
            os.system(cmd)
        """
        )[0]
        is Status.CONFIRMED
    )


def test_sanitizer_suppresses_only_its_class():
    assert verdict(
        """
        def f():
            os.system("ping " + shlex.quote(input()))
        """
    ) == (Status.SUPPRESSED, SANITIZED)
    assert (
        verdict(
            """
        def f():
            eval(shlex.quote(input()))
        """
        )[0]
        is Status.CONFIRMED
    )  # shell quoting does not make code safe to eval


def test_sanitized_mixed_with_tainted_is_not_sanitized():
    assert (
        verdict(
            """
        def f():
            os.system(shlex.quote(input()) + input())
        """
        )[0]
        is Status.CONFIRMED
    )


def test_numeric_cast_sanitizes_everything():
    assert verdict(
        """
        def f(cur):
            cur.execute("SELECT * FROM t WHERE id = %d" % int(input()))
        """
    ) == (Status.SUPPRESSED, SANITIZED)


def test_unknown_call_propagates_taint_but_is_not_constant():
    assert (
        verdict(
            """
        def f():
            os.system(build(input()))
        """
        )[0]
        is Status.CONFIRMED
    )
    assert verdict(
        """
        def f():
            os.system(build("x"))
        """
    ) == (Status.CANDIDATE, None)


def test_mutation_methods_taint_container():
    assert (
        verdict(
            """
        def f(cur):
            parts = ["SELECT * FROM t WHERE"]
            parts.append(input())
            cur.execute(" ".join(parts))
        """
        )[0]
        is Status.CONFIRMED
    )


def test_comprehension_variables_follow_their_iterable():
    findings = scan(
        """
        def f():
            [os.system(c) for c in sys.argv]
            [os.system(c) for c in ["ls", "pwd"]]
        """
    )
    assert [f.status for f in findings] == [Status.CONFIRMED, Status.SUPPRESSED]


def test_walrus_assignment():
    assert (
        verdict(
            """
        def f():
            if (cmd := input()):
                os.system(cmd)
        """
        )[0]
        is Status.CONFIRMED
    )


def test_module_constants_used_in_functions():
    assert verdict(
        """
        BASE = "ls -la"

        def f():
            os.system(BASE)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


def test_module_global_rebinding_disables_constant():
    assert verdict(
        """
        CMD = "ls"

        def set_cmd(value):
            global CMD
            CMD = value

        def f():
            os.system(CMD)
        """
    ) == (Status.CANDIDATE, None)


def test_dead_code_after_return_is_left_alone():
    assert verdict(
        """
        def f(cmd):
            return
            os.system(cmd)
        """
    ) == (Status.CANDIDATE, None)


def test_lambda_class_body_and_decorator_sinks():
    findings = scan(
        """
        run = lambda: os.system(input())

        class Job:
            command = "ls"
            os.system(command)

        def outer():
            @deco(eval(input()))
            def inner():
                pass
        """
    )
    assert [(f.rule_id, f.status) for f in findings] == [
        ("VH-CMDI-001", Status.CONFIRMED),
        ("VH-CMDI-001", Status.SUPPRESSED),
        ("VH-CODEI-001", Status.CONFIRMED),
    ]


def test_route_handler_parameters_are_sources():
    assert (
        verdict(
            """
        @app.route("/x/<cmd>")
        def handler(cmd):
            os.system(cmd)
        """
        )[0]
        is Status.CONFIRMED
    )


def test_taint_can_be_disabled():
    (f,) = scan("def f():\n    os.system(input())\n", taint=False)
    assert f.status is Status.CANDIDATE


def test_weak_crypto_is_never_touched_by_taint():
    (f,) = scan('import hashlib\nhashlib.md5(b"constant")\n')
    assert f.status is Status.CANDIDATE


# -- inline suppressions ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("comment", "suppressed"),
    [
        ("# vulnhawk: ignore", True),
        ("# vulnhawk: ignore[VH-CMDI-001]", True),
        ("# vulnhawk: ignore[VH-SQLI-001, VH-CMDI-001]", True),
        ("# vulnhawk: ignore[VH-SQLI-001]", False),
        ("# VulnHawk: Ignore", True),
    ],
)
def test_inline_directives(comment: str, suppressed: bool):
    (f,) = scan(f"def f():\n    os.system(input())  {comment}\n")
    assert (f.status is Status.SUPPRESSED) is suppressed
    if suppressed:
        assert f.suppression == INLINE


def test_inline_directive_on_closing_line_of_multiline_call():
    (f,) = scan(
        """
        def f():
            os.system(
                input()
            )  # vulnhawk: ignore
        """
    )
    assert f.suppression == INLINE


def test_directive_inside_string_does_not_count():
    (f,) = scan('def f():\n    os.system(input() + "# vulnhawk: ignore")\n')
    assert f.status is Status.CONFIRMED
