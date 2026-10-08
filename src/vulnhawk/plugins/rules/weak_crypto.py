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
        name = ctx.call_name(node)
        if name in WEAK_CONSTRUCTORS:
            algorithm = WEAK_CONSTRUCTORS[name]
        elif name == "hashlib.new":
            arg = first_arg(node, "name")
            if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                return
            algorithm = arg.value.lower().replace("-", "")
            if algorithm not in WEAK_ALGORITHMS:
                return
        else:
            return
        flag = keyword(node, "usedforsecurity")
        if isinstance(flag, ast.Constant) and flag.value is False:
            return
        yield Match(node, f"Weak hash algorithm {algorithm.upper()} is used.")
