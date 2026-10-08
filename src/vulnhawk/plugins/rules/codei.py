"""Code injection: non-constant input to eval/exec/compile.

Any non-constant argument is a candidate; the taint pass decides.
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
)

CODE_FUNCTIONS = frozenset(
    {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}
)


class CodeInjection(RulePlugin):
    rule_id = "VH-CODEI-001"
    name = "code-injection"
    description = "Non-constant input is evaluated as Python code."
    severity = Severity.HIGH
    cwe = ("CWE-95",)
    default_confidence = 70

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        matched = sorted(ctx.call_names(node) & CODE_FUNCTIONS)
        if not matched:
            return
        name = matched[0]
        code = first_arg(node, "source")
        if code is None or is_constant(code):
            return
        func = name.rsplit(".", 1)[-1]
        if is_dynamic_string(code):
            message = f"String built from non-constant parts is passed to {func}()."
            yield Match(node, message, arg=code)
        else:
            label = ctx.segment(code)
            message = f"Non-constant `{label}` is passed to {func}()."
            yield Match(node, message, confidence=55, arg=code)
