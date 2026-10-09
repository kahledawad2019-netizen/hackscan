from __future__ import annotations

import textwrap

import pytest

from hackscan.analyzers.ast_pass import analyze_source
from hackscan.analyzers.suppressions import INLINE
from hackscan.analyzers.taint_pass import CONSTANT_INPUT, SANITIZED
from hackscan.core.models import Status
from hackscan.plugins.loader import builtin_plugins

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


def test_shell_quoting_is_kept_visible_at_low_confidence():
    (f,) = scan(
        """
        def f():
            os.system("ping " + shlex.quote(input()))
        """
    )
    assert f.status is Status.CANDIDATE  # POSIX-only protection: never suppressed
    assert f.confidence == 20
    assert any("POSIX" in e.message for e in f.evidence)


def test_sanitizer_applies_only_to_its_class():
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


def test_loop_else_runs_only_without_break():
    assert verdict(
        """
        def f(items):
            cmd = "ls"
            for item in items:
                if item:
                    break
            else:
                cmd = "pwd"
            os.system(cmd)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


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
        ("HS-CMDI-001", Status.CONFIRMED),
        ("HS-CMDI-001", Status.SUPPRESSED),
        ("HS-CODEI-001", Status.CONFIRMED),
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
        ("# hackscan: ignore", True),
        ("# hackscan: ignore[HS-CMDI-001]", True),
        ("# hackscan: ignore[HS-SQLI-001, HS-CMDI-001]", True),
        ("# hackscan: ignore[HS-SQLI-001]", False),
        ("# HackScan: Ignore", True),
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
            )  # hackscan: ignore
        """
    )
    assert f.suppression == INLINE


def test_directive_inside_string_does_not_count():
    (f,) = scan('def f():\n    os.system(input() + "# hackscan: ignore")\n')
    assert f.status is Status.CONFIRMED


# -- soundness regressions (Codex M2 review + related cases) -------------------------------
# Each of these must NOT be suppressed: attacker input can reach the sink.

NOT_SUPPRESSED_CASES = {
    "shlex.quote inside double quotes": """
        def f():
            os.system('echo "' + shlex.quote(input()) + '"')
        """,
    "shlex.quote inside f-string quotes": """
        def f():
            os.system(f'echo "{shlex.quote(input())}"')
        """,
    "shlex.quote with quoted template variable": """
        def f():
            prefix = 'echo "'
            os.system(prefix + shlex.quote(input()))
        """,
    "aliased list mutation": """
        def f():
            parts = ["echo "]
            alias = parts
            alias.append(input())
            os.system("".join(parts))
        """,
    "mutation inside an assignment": """
        def f():
            parts = ["echo "]
            result = parts.append(input())
            os.system("".join(parts))
        """,
    "list passed to an unmodeled call": """
        def f():
            parts = ["echo "]
            fill(parts)
            os.system("".join(parts))
        """,
    "list stored on another object": """
        def f(holder):
            parts = ["echo "]
            holder.items = parts
            holder.refresh()
            os.system("".join(parts))
        """,
    "nested list mutation": """
        def f():
            rows = [["echo "]]
            row = rows[0]
            row.append(input())
            os.system("".join(rows[0]))
        """,
    "nonlocal rebinding in a closure": """
        def f():
            cmd = "ls"
            def change():
                nonlocal cmd
                cmd = input()
            change()
            os.system(cmd)
        """,
    "closure mutating a captured list": """
        def f():
            parts = ["echo "]
            def add():
                parts.append(input())
            add()
            os.system("".join(parts))
        """,
    "module list mutated by another function": """
        CMD = ["echo "]

        def set_cmd():
            CMD.append(input())

        def run_cmd():
            os.system("".join(CMD))
        """,
    "module-level list mutated via a function call": """
        CMD = ["echo "]

        def add():
            CMD.append(input())

        add()
        os.system("".join(CMD))
        """,
    "exception raised after taint": """
        def f():
            cmd = "echo safe"
            try:
                cmd = input()
                raise ValueError()
            except ValueError:
                os.system(cmd)
        """,
    "finally after tainted early return": """
        def f():
            cmd = "echo safe"
            try:
                cmd = input()
                return
            finally:
                os.system(cmd)
        """,
    "exception inside nested branch": """
        def f(flag):
            cmd = "echo safe"
            try:
                if flag:
                    cmd = input()
                    risky()
                cmd = "echo reset"
            except Exception:
                os.system(cmd)
        """,
    "list held by dict() constructor": """
        def f():
            parts = ["echo "]
            wrapper = dict(cmd=parts)
            wrapper["cmd"].append(input())
            os.system("".join(parts))
        """,
    "list held by unknown wrapper call": """
        def f():
            parts = ["echo "]
            box = Box(parts)
            box.items.append(input())
            os.system("".join(parts))
        """,
    "nested finally before outer handler": """
        def f():
            cmd = "echo safe"
            try:
                try:
                    raise ValueError()
                finally:
                    cmd = input()
            except ValueError:
                os.system(cmd)
        """,
    "break skips the reset": """
        def f():
            cmd = "echo safe"
            while True:
                cmd = input()
                if cmd:
                    break
                cmd = "echo safe"
            os.system(cmd)
        """,
    "break from for loop": """
        def f(items):
            cmd = "echo safe"
            for item in items:
                cmd = input()
                if item:
                    break
                cmd = "echo safe"
            os.system(cmd)
        """,
    "continue skips the reset": """
        def f(items):
            cmd = "echo safe"
            for item in items:
                os.system(cmd)
                cmd = input()
                if item:
                    continue
                cmd = "echo safe"
        """,
    "walrus in the same condition as the sink": """
        def f():
            cmd = "echo safe"
            if (cmd := input()) and os.system(cmd):
                pass
        """,
}


@pytest.mark.parametrize("code", NOT_SUPPRESSED_CASES.values(), ids=NOT_SUPPRESSED_CASES.keys())
def test_no_unsound_suppression(code: str):
    findings = [f for f in scan(code) if f.rule_id == "HS-CMDI-001"]
    assert findings
    assert all(f.status is not Status.SUPPRESSED for f in findings), [
        (f.status, f.suppression) for f in findings
    ]


def test_literal_eval_is_not_an_eval_sanitizer():
    (f,) = scan("import ast\n\ndef f():\n    eval(ast.literal_eval(input()))\n")
    assert f.status is Status.CONFIRMED


def test_shlex_quote_in_plain_context_is_low_confidence():
    (f,) = scan(
        """
        def f():
            os.system("ls -l " + shlex.quote(input()) + " | wc -l")
        """
    )
    assert (f.status, f.confidence) == (Status.CANDIDATE, 20)


@pytest.mark.parametrize(
    "expr",
    [
        'shlex.quote(input()).strip("\'")',
        "repr(shlex.quote(input()))",
        "shlex.quote(input())[1:-1]",
        'shlex.quote(input()).replace("\'", "")',
    ],
)
def test_transforming_quoted_values_drops_quoting(expr: str):
    (f,) = scan(f"def f():\n    os.system({expr})\n")
    assert f.status is Status.CONFIRMED


def test_immutable_values_survive_calls_and_closures():
    assert verdict(
        """
        def f():
            cmd = "ls"
            log(cmd)
            def show():
                print(cmd)
            show()
            os.system(cmd)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


def test_read_only_list_use_keeps_constant():
    assert verdict(
        """
        def f():
            parts = ["ls", "-la"]
            n = len(parts)
            os.system(" ".join(parts))
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


def test_django_class_view_self_request_is_a_source():
    assert (
        verdict(
            """
        class Run(View):
            def post(self, request):
                os.system(self.request.POST["cmd"])
        """
        )[0]
        is Status.CONFIRMED
    )


@pytest.mark.parametrize(
    "code",
    [
        # a mapping rest capture takes the subject
        """
        def f():
            rest = {"cmd": "echo safe"}
            match {"cmd": input()}:
                case {**rest}:
                    os.system(rest["cmd"])
        """,
        # a failed pattern may leave earlier captures bound for later code
        """
        def f():
            x = "ls"
            match [input(), 2]:
                case [x, 1]:
                    return
                case _:
                    pass
            os.system(x)
        """,
        # a false guard keeps the capture for the next case
        """
        def f():
            x = "ls"
            match input():
                case x if len(x) > 99:
                    pass
                case _:
                    os.system(x)
        """,
        # no case matched: captures of failed cases are still visible
        """
        def f():
            x = "ls"
            match (input(), 1):
                case (x, 2):
                    return
            os.system(x)
        """,
    ],
)
def test_match_captures_are_not_suppressed(code):
    assert verdict(code)[0] is Status.CONFIRMED


def test_match_constant_subject_still_suppressed():
    assert verdict(
        """
        def f():
            match "ls":
                case x:
                    os.system(x)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


@pytest.mark.parametrize(
    "code",
    [
        # a short-circuited `:=` may not run
        """
        def f():
            x = input()
            if len(x) > 5 and (x := "ls"):
                pass
            os.system(x)
        """,
        """
        def f():
            x = input()
            if x or (x := "ls"):
                pass
            os.system(x)
        """,
        """
        def f():
            x = input()
            y = (x := "ls") if len(x) > 5 else "a"
            os.system(x)
        """,
        # a comprehension body may run zero times
        """
        def f():
            x = input()
            [(x := "ls") for _ in sys.argv[1:]]
            os.system(x)
        """,
        # ... or several times, each seeing the previous
        """
        def f():
            x = "ls"
            y = "a"
            [(x := y, y := input()) for _ in sys.argv[1:]]
            os.system(x)
        """,
        # a guard's `:=` behind `and`
        """
        def f():
            match input():
                case x if len(x) > 99 and (x := "ls"):
                    pass
                case _:
                    pass
            os.system(x)
        """,
        # a capture aliases the (mutable) subject
        """
        def f():
            parts = ["ls"]
            match parts:
                case y:
                    y.append(input())
            os.system(" ".join(parts))
        """,
    ],
)
def test_conditional_walrus_and_capture_aliases_are_not_suppressed(code):
    assert verdict(code)[0] is not Status.SUPPRESSED


def test_scope_with_walrus_never_suppresses_but_still_confirms():
    # `:=` can rebind mid-expression; the statement-level model cannot order that, so
    # a scope with its own `:=` keeps its sinks visible.
    assert verdict(
        """
        def f():
            if (x := "ls"):
                os.system(x)
        """
    ) == (Status.CANDIDATE, None)
    assert (
        verdict(
            """
        def f():
            if (x := input()):
                os.system(x)
        """
        )[0]
        is Status.CONFIRMED
    )
    # Only the scope that owns the `:=` is affected.
    assert verdict(
        """
        def g():
            return [y := 1]

        def f():
            cmd = "ls"
            os.system(cmd)
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


@pytest.mark.parametrize(
    "code",
    [
        # comprehension filter assigns, empty inner iterable skips the element
        """
        def f():
            x = "safe"
            [(x := "safe") for _ in [1] if (x := input()) for j in []]
            os.system(x)
        """,
        # chained comparison skips later comparators
        """
        def f():
            x = input()
            0 > 1 > (x := "safe")
            os.system(x)
        """,
        # an assert message runs only on failure
        """
        def f():
            x = input()
            assert True, (x := "safe")
            os.system(x)
        """,
        # lambda defaults run at creation
        """
        def f():
            x = "safe"
            callback = lambda arg=(x := input()): arg
            os.system(x)
        """,
        # a later `:=` does not change an operand evaluated before it
        """
        def f():
            x = input()
            command = f"{x}{(x := '')}"
            os.system(command)
        """,
        """
        def f():
            x = input()
            values = [x, (x := "safe")]
            os.system(values[0])
        """,
        # `:=` at module level: module constants are not trusted
        """
        x = input()
        0 > 1 > (x := "ls")

        def f():
            os.system(x)
        """,
        # a generator body runs when consumed, after `x` was rebound
        """
        def f():
            x = "safe"
            pending = (os.system(x) for _ in [1])
            x = input()
            list(pending)
        """,
        # nested scopes reading an enclosing local that shadows a module constant
        """
        x = "ls"

        def f():
            x = input()
            g = lambda: os.system(x)
        """,
        """
        x = "ls"

        def f():
            x = input()

            def g():
                os.system(x)
        """,
    ],
)
def test_walrus_ordering_and_deferred_code_are_not_suppressed(code):
    assert verdict(code)[0] is not Status.SUPPRESSED


def test_module_constant_still_suppresses_in_functions_and_nested_scopes():
    findings = scan(
        """
        CMD = "ls"

        def f():
            os.system(CMD)

        def g():
            def h():
                os.system(CMD)
        """
    )
    assert [(f.status, f.suppression) for f in findings] == [
        (Status.SUPPRESSED, CONSTANT_INPUT),
        (Status.SUPPRESSED, CONSTANT_INPUT),
    ]


@pytest.mark.parametrize(
    "code",
    [
        # a generator's values are produced when consumed
        """
        def f():
            x = "safe"
            pending = (x for _ in [1])
            x = input()
            os.system("".join(pending))
        """,
        # a comprehension target shadows the outer name
        """
        def f():
            x = "safe"
            [os.system(x) for x in [input()]]
        """,
        # class-body names are invisible inside its comprehensions
        """
        x = input()

        class C:
            x = "safe"
            [os.system(x) for _ in [1]]
        """,
        # a function may run before a later module rebinding
        """
        x = input()

        def f():
            os.system(x)

        f()
        x = "safe"
        """,
        # a sibling function rebinds a declared global between assignment and use
        """
        def change():
            global x
            x = input()

        def f():
            global x
            x = "safe"
            change()
            os.system(x)
        """,
        # ... or a sibling closure rebinds a nonlocal
        """
        def outer():
            x = "safe"

            def change():
                nonlocal x
                x = input()

            def use():
                nonlocal x
                x = "safe"
                change()
                os.system(x)
        """,
        # the module namespace written dynamically
        """
        x = "safe"
        globals()["x"] = input()

        def f():
            os.system(x)
        """,
        """
        x = "safe"
        exec("x = input()")
        os.system(x)
        """,
    ],
)
def test_deferred_and_shared_bindings_are_not_suppressed(code):
    assert all(f.status is not Status.SUPPRESSED for f in scan(code))


@pytest.mark.parametrize(
    "code",
    [
        # namespace writers under another name
        """
        from builtins import exec as execute

        cmd = "echo safe"
        execute("cmd = input()")
        os.system(cmd)

        def run():
            os.system(cmd)
        """,
        """
        import builtins

        cmd = "echo safe"
        builtins.exec("cmd = input()")
        os.system(cmd)
        """,
        """
        from importlib import import_module

        cmd = "echo safe"
        import_module("builtins").exec("cmd = input()")
        os.system(cmd)
        """,
        # `locals()` in a class body writes the class namespace
        """
        class Commands:
            cmd = "echo safe"
            locals()["cmd"] = input()
            os.system(cmd)
        """,
        # a comprehension target rebound by a later `for`
        """
        commands = {"startup": [input()]}
        [os.system(cmd) for cmd in ["startup"] for cmd in commands[cmd]]
        """,
    ],
)
def test_namespace_aliases_and_rebound_comprehension_targets(code):
    assert all(f.status is not Status.SUPPRESSED for f in scan(code))


def test_single_comprehension_target_still_resolves():
    assert verdict(
        """
        def f():
            [os.system(cmd) for cmd in ["ls", "pwd"]]
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)


@pytest.mark.parametrize(
    "code",
    [
        # a namespace writer aliased outside the class body
        """
        execute = exec

        class Commands:
            cmd = "echo safe"
            execute("cmd = input()")
            os.system(cmd)
        """,
        """
        namespace = locals

        class Commands:
            cmd = "echo safe"
            namespace()["cmd"] = input()
            os.system(cmd)
        """,
        # a namespace attribute imported under another name
        """
        from builtins import __dict__ as builtin_names

        cmd = "echo safe"
        builtin_names["exec"]("cmd = input()")
        os.system(cmd)
        """,
        # comprehension filters run before the element
        """
        def run():
            parts = ["echo safe"]
            [os.system(" ".join(parts)) for _ in [1] if not parts.append(input())]
        """,
        # ... and later items see earlier items' mutations
        """
        def run():
            parts = ["echo safe"]
            [(os.system(" ".join(parts)), parts.append(input())) for _ in range(2)]
        """,
        # mutation through a comprehension target reaches the container
        """
        def run():
            commands = [["echo safe"]]
            [cmd.append(input()) for cmd in commands]
            os.system(" ".join(commands[0]))
        """,
    ],
)
def test_namespace_alias_and_comprehension_order(code):
    assert all(f.status is not Status.SUPPRESSED for f in scan(code))


@pytest.mark.parametrize(
    "code",
    [
        # a writer alias made with `:=`
        """
        (execute := exec)

        class Commands:
            cmd = "echo safe"
            execute("cmd = input()")
            os.system(cmd)
        """,
        # an item mutated in place through a nested generator / a literal iterable
        """
        def run():
            commands = [["echo safe"]]
            [cmd.append(input()) for group in [commands] for cmd in group]
            os.system(" ".join(commands[0]))
        """,
        """
        def run():
            [os.system(" ".join(cmd)) for cmd in [["echo safe"]] if not cmd.append(input())]
        """,
        # a subscript comprehension target stores into the container
        """
        def run():
            commands = [["echo safe"]]
            [None for commands[0] in [[input()]]]
            os.system(" ".join(commands[0]))
        """,
    ],
)
def test_comprehension_item_mutation_and_walrus_alias(code):
    assert all(f.status is not Status.SUPPRESSED for f in scan(code))


@pytest.mark.parametrize(
    "code",
    [
        # an item passed inside a container to code that may change it
        """
        def change(items):
            items[0].append(input())

        def run():
            commands = [["echo safe"]]
            [change([cmd]) for cmd in commands]
            os.system(" ".join(commands[0]))
        """,
        # a mutation through an accessor's result
        """
        def run():
            commands = {"cmd": ["echo safe"]}
            [group.get("cmd").append(input()) for group in [commands]]
            os.system(" ".join(commands["cmd"]))
        """,
        """
        def run():
            commands = {"cmd": ["echo safe"]}
            commands.get("cmd").append(input())
            os.system(" ".join(commands["cmd"]))
        """,
        """
        def run():
            commands = {"cmd": ["echo safe"]}
            commands.setdefault("cmd", [])[0] = input()
            os.system(" ".join(commands["cmd"]))
        """,
    ],
)
def test_mutation_through_wrapped_items_and_accessors(code):
    assert all(f.status is not Status.SUPPRESSED for f in scan(code))


@pytest.mark.parametrize(
    "code",
    [
        # a bound method taken off a mutable object
        """
        def run():
            parts = ["echo safe"]
            append = parts.append
            append(input())
            os.system(" ".join(parts))
        """,
        """
        def run():
            commands = {"cmd": ["echo safe"]}
            append = commands.get("cmd").append
            append(input())
            os.system(" ".join(commands["cmd"]))
        """,
        # a compound receiver
        """
        def run():
            first = ["echo safe"]
            second = ["echo other"]
            (first if input() == "first" else second).append(input())
            os.system(" ".join(first))
        """,
        """
        def run():
            commands = [["echo safe"]]
            [[cmd][0].append(input()) for cmd in commands]
            os.system(" ".join(commands[0]))
        """,
    ],
)
def test_bound_method_aliases_and_compound_receivers(code):
    assert all(f.status is not Status.SUPPRESSED for f in scan(code))


def test_calling_a_method_directly_is_not_an_escape():
    assert verdict(
        """
        def run():
            parts = ["ls"]
            parts.append("-l")
            os.system(" ".join(parts))
        """
    ) == (Status.SUPPRESSED, CONSTANT_INPUT)
