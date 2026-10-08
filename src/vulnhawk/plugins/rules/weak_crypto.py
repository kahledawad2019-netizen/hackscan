"""Weak cryptography: MD5/SHA-1 hashing, unless explicitly marked non-security."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from vulnhawk.core.models import Severity
from vulnhawk.plugins.base import FileContext, Match, RulePlugin, first_arg, keyword

WEAK_ALGORITHMS = frozenset({"md5", "sha1", "md4", "md2"})
WEAK_CONSTRUCTORS = {f"hashlib.{alg}": alg for alg in WEAK_ALGORITHMS}


class WeakHash(RulePlugin):
    rule_id = "VH-CRYPTO-001"
    name = "weak-hash"
    description = "A cryptographically broken hash (MD5/SHA-1) is used."
    severity = Severity.LOW
    cwe = ("CWE-328",)
    default_confidence = 80

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        names = ctx.call_names(node)
        confidence = None
        if constructors := sorted(names & WEAK_CONSTRUCTORS.keys()):
            algorithm = WEAK_CONSTRUCTORS[constructors[0]]
        elif "hashlib.new" in names:
            arg = first_arg(node, "name")
            literals = [arg]
            if isinstance(arg, ast.Name):
                # Find a literal algorithm name bound locally (never used to dismiss).
                literals = ctx.assignments_before(arg.id, node)
                confidence = 60
            weak = sorted({_normalize(v.value) for v in literals if _is_str(v)} & WEAK_ALGORITHMS)
            if not weak:
                return
            algorithm = weak[0]
        else:
            return
        flag = keyword(node, "usedforsecurity")
        if isinstance(flag, ast.Constant) and flag.value is False:
            return
        yield Match(node, f"Weak hash algorithm {algorithm.upper()} is used.", confidence)


def _is_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _normalize(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "")
