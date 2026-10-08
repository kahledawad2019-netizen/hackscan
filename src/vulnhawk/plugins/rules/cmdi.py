"""Command injection: non-constant commands run through a shell."""

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
        name = ctx.call_name(node)
        if name in SHELL_FUNCTIONS:
            via = name
        elif name in SUBPROCESS_FUNCTIONS and _shell_enabled(node):
            via = f"{name}(shell=True)"
        else:
            return
        command = first_arg(node, "args") or first_arg(node, "cmd")
        if command is None or is_constant(command):
            return
        if isinstance(command, ast.Name):
            values = ctx.assignments_before(command.id, node)
            if values and all(is_constant(v) for v in values):
                return
            dynamic = any(is_dynamic_string(v) for v in values)
            yield Match(
                node,
                f"Command `{command.id}` is executed via {via}.",
                confidence=65 if dynamic else 50,
            )
            return
        yield Match(node, f"Non-constant command is executed via {via}.")


def _shell_enabled(call: ast.Call) -> bool:
    shell = keyword(call, "shell")
    if shell is None:
        return False
    return not (isinstance(shell, ast.Constant) and not shell.value)
