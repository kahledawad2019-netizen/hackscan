"""Command injection: non-constant commands run through a shell.

Any non-constant command at a shell sink is a candidate; the taint pass decides whether
it is attacker-controlled, constant or sanitized.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from vulnhawk.core.models import Severity
from vulnhawk.plugins.base import (
    FileContext,
    Match,
    RulePlugin,
    first_arg,
    is_constant,
    is_dynamic_string,
    keyword,
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
    rule_id = "VH-CMDI-001"
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
        elif (proc := sorted(names & SUBPROCESS_FUNCTIONS)) and _shell_enabled(node):
            via = f"{proc[0]}(shell=True)"
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


def _shell_enabled(call: ast.Call) -> bool:
    shell = keyword(call, "shell")
    if shell is None:
        return False
    return not (isinstance(shell, ast.Constant) and not shell.value)
