"""Command injection: non-constant commands run through a shell.

Any non-constant command at a shell sink is a candidate; the taint pass decides whether
it is attacker-controlled, constant or sanitized.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from hackscan.core.models import Severity
from hackscan.plugins.base import (
    FileContext,
    Match,
    RulePlugin,
    first_arg,
    is_constant,
    is_dynamic_string,
    keyword,
    same_binding,
)

# Always interpreted by a shell.
SHELL_FUNCTIONS = frozenset(
    {
        "os.system",
        "os.popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "commands.getoutput",
        "commands.getstatusoutput",
        "asyncio.create_subprocess_shell",
    }
)
# Shell only when called with shell=True (or a non-constant shell flag).
SUBPROCESS_FUNCTIONS = frozenset(
    {
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
    }
)


class CommandInjection(RulePlugin):
    rule_id = "HS-CMDI-001"
    name = "command-injection"
    description = "A non-constant command string is executed through a system shell."
    severity = Severity.HIGH
    cwe = ("CWE-78",)
    default_confidence = 70

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        names = ctx.call_names(node)
        if shell := sorted(names & SHELL_FUNCTIONS):
            via = shell[0]
        elif (proc := sorted(names & SUBPROCESS_FUNCTIONS)) and (
            shell := _shell_enabled(node, ctx)
        ):
            via = (
                f"{proc[0]}(shell=True)"
                if shell == "keyword"
                else f"{proc[0]}(shell enabled through ** unpacking)"
            )
        else:
            return
        command = first_arg(node, "args") or first_arg(node, "cmd")
        if command is None or is_constant(command):
            return
        if is_dynamic_string(command):
            message = f"Command built from non-constant parts is executed via {via}."
            yield Match(node, message, arg=command)
        else:
            label = ctx.segment(command)
            message = f"Non-constant command `{label}` is executed via {via}."
            yield Match(node, message, confidence=50, arg=command)


def _shell_enabled(call: ast.Call, ctx: FileContext) -> str | None:
    """ "keyword" (a `shell=` argument that may be true), "unpacked" (a `shell` value given
    through `**`), or None."""
    shell = keyword(call, "shell")
    if shell is not None:
        return None if _false_constant(shell) else "keyword"
    if any(not _false_constant(value) for value in _unpacked_shell_values(call, ctx)):
        return "unpacked"
    return None


def _false_constant(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Constant) and not expr.value


def _unpacked_shell_values(call: ast.Call, ctx: FileContext) -> list[ast.expr]:
    """`shell` values a call receives through `**` unpacking: a dict literal, or a dict
    variable given a `shell` entry wherever the same variable is bound (`kw['shell'] = ...`,
    `kw = {'shell': ...}`, `kw = dict(shell=...)`, `kw.update(shell=...)`,
    `kw.setdefault('shell', ...)`). An unpacked dict whose contents are unknown (a
    parameter) yields nothing. Flow-insensitive and alias-blind (documented in the tests)."""
    values: list[ast.expr] = []
    unpacked: list[ast.Name] = []
    for kw in call.keywords:
        if kw.arg is not None:
            continue
        if isinstance(kw.value, ast.Name):
            unpacked.append(kw.value)
        else:
            values.extend(_dict_shell_values(kw.value, ctx))
    if not unpacked:
        return values

    def same(expr: ast.AST) -> bool:
        return any(
            isinstance(expr, ast.Name) and expr.id == u.id and same_binding(ctx, expr, u)
            for u in unpacked
        )

    for node in ast.walk(ctx.tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if same(target):
                    values.extend(_dict_shell_values(node.value, ctx))
                elif (
                    isinstance(target, ast.Subscript)
                    and same(target.value)
                    and _is_shell_key(target.slice)
                ):
                    values.append(node.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and same(node.func.value)
        ):
            if node.func.attr == "update":
                values.extend(k.value for k in node.keywords if k.arg == "shell")
                for arg in node.args:
                    values.extend(_dict_shell_values(arg, ctx))
            elif (
                node.func.attr == "setdefault"
                and len(node.args) == 2
                and _is_shell_key(node.args[0])
            ):
                values.append(node.args[1])
    return values


def _dict_shell_values(expr: ast.AST, ctx: FileContext) -> list[ast.expr]:
    """The effective `shell` value of a dict literal (the last literal `shell` key wins) or of
    a call that may be the builtin `dict` (its `shell=` keyword, else its dict-literal argument). A
    later `**other` inside the literal might override it; that stays evidence (a finding is
    never dismissed on it)."""
    if isinstance(expr, ast.Dict):
        values = [
            v
            for k, v in zip(expr.keys, expr.values, strict=True)
            if k is not None and _is_shell_key(k)
        ]
        return values[-1:]
    if isinstance(expr, ast.Call) and ctx.call_names(expr) & {"dict", "builtins.dict"}:
        keywords = [k.value for k in expr.keywords if k.arg == "shell"]
        if keywords:
            return keywords[-1:]
        return _dict_shell_values(expr.args[0], ctx) if len(expr.args) == 1 else []
    return []


def _is_shell_key(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Constant) and expr.value == "shell"
