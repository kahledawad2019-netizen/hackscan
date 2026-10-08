"""SQL injection: dynamically built SQL passed to a DB execution sink."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from vulnhawk.core.models import Severity
from vulnhawk.plugins.base import FileContext, Match, RulePlugin, first_arg, is_dynamic_string

# Method names that execute raw SQL on DB-API cursors/connections, Django and pandas.
SQL_METHODS = frozenset(
    {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
)
# Fully-qualified functions that wrap raw SQL text.
SQL_FUNCTIONS = frozenset({"sqlalchemy.text", "sqlalchemy.sql.text", "pandas.read_sql"})


class SqlInjection(RulePlugin):
    rule_id = "VH-SQLI-001"
    name = "sql-injection"
    description = "SQL query built from dynamic strings is passed to a database execution call."
    severity = Severity.HIGH
    cwe = ("CWE-89",)
    default_confidence = 70

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        if not _is_sql_sink(node, ctx):
            return
        query = first_arg(node, "sql") or first_arg(node, "query")
        if query is None:
            return
        if is_dynamic_string(query):
            yield Match(node, "SQL query is built with string formatting/concatenation.")
        elif isinstance(query, ast.Name) and any(
            is_dynamic_string(v) for v in ctx.assignments_before(query.id, node)
        ):
            yield Match(
                node,
                f"SQL query `{query.id}` is built with string formatting/concatenation.",
                confidence=60,
            )


def _is_sql_sink(call: ast.Call, ctx: FileContext) -> bool:
    name = ctx.call_name(call)
    if name in SQL_FUNCTIONS:
        return True
    return isinstance(call.func, ast.Attribute) and call.func.attr in SQL_METHODS
