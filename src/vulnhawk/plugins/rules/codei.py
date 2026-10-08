"""Code injection: non-constant input to eval/exec/compile."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from vulnhawk.core.models import Severity
from vulnhawk.plugins.base import FileContext, Match, RulePlugin, first_arg, is_constant

CODE_FUNCTIONS = frozenset({"eval", "exec", "compile", "builtins.eval", "builtins.exec"})


class CodeInjection(RulePlugin):
    rule_id = "VH-CODEI-001"
    name = "code-injection"
    description = "Non-constant input is evaluated as Python code."
    severity = Severity.HIGH
    cwe = ("CWE-95",)
    default_confidence = 70

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        name = ctx.call_name(node)
        if name not in CODE_FUNCTIONS:
            return
        code = first_arg(node, "source")
        if code is None or is_constant(code):
            return
        func = name.rsplit(".", 1)[-1]
        if isinstance(code, ast.Name):
            values = ctx.assignments_before(code.id, node)
            if values and all(is_constant(v) for v in values):
                return
            yield Match(node, f"`{code.id}` is passed to {func}().", confidence=55)
            return
        yield Match(node, f"Non-constant expression is passed to {func}().")
