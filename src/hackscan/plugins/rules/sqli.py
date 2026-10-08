"""SQL injection: non-constant SQL reaching a DB execution sink.

Candidates:
- string formatting/concatenation at the sink, when the receiver looks like a DB object
  or the literal parts look like SQL (confidence 70);
- any other non-constant query (variable, call result, attribute) passed to a DB-looking
  receiver (confidence 40). The taint pass confirms or suppresses these.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from hackscan.core.models import Severity
from hackscan.plugins.base import (
    FileContext,
    Match,
    RulePlugin,
    first_arg,
    has_sql_text,
    is_constant,
    is_string_formatting,
)

# Method names that execute raw SQL on DB-API cursors/connections, Django and pandas.
SQL_METHODS = frozenset(
    {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query"}
)
# Fully-qualified functions that take raw SQL text.
SQL_FUNCTIONS = frozenset(
    {"sqlalchemy.text", "sqlalchemy.sql.text", "pandas.read_sql", "pandas.read_sql_query"}
)
DB_MODULES = (
    "sqlite3",
    "psycopg2",
    "psycopg",
    "pymysql",
    "MySQLdb",
    "mysql.connector",
    "cx_Oracle",
    "oracledb",
    "sqlalchemy",
    "django.db",
    "asyncpg",
    "aiosqlite",
)
_DB_NAME_RE = re.compile(
    r"(^|_)(cur|curs|cursor|conn|connection|db|database|session|engine|objects|tx|transaction)s?$",
    re.IGNORECASE,
)


class SqlInjection(RulePlugin):
    rule_id = "HS-SQLI-001"
    name = "sql-injection"
    description = "Non-constant SQL is passed to a database execution call."
    severity = Severity.HIGH
    cwe = ("CWE-89",)
    default_confidence = 70

    def check(self, node: ast.AST, ctx: FileContext) -> Iterable[Match]:
        assert isinstance(node, ast.Call)
        strong = bool(ctx.call_names(node) & SQL_FUNCTIONS)
        method = isinstance(node.func, ast.Attribute) and node.func.attr in SQL_METHODS
        if not (strong or method):
            return
        query = first_arg(node, "sql") or first_arg(node, "query")
        if query is None or is_constant(query):
            return
        if isinstance(query, ast.Call) and ctx.call_names(query) & SQL_FUNCTIONS:
            return  # e.g. session.execute(text(...)): reported at the inner text() call
        db_receiver = strong or _is_db_receiver(node.func, ctx)

        if is_string_formatting(query):
            if db_receiver or has_sql_text(query):
                yield Match(
                    node, "SQL query is built with string formatting/concatenation.", arg=query
                )
            return
        if db_receiver:
            yield Match(
                node,
                f"Non-constant query `{_short(ctx.segment(query))}` reaches a SQL sink.",
                confidence=40,
                arg=query,
            )


def _is_db_receiver(func: ast.expr, ctx: FileContext) -> bool:
    if not isinstance(func, ast.Attribute):
        return False
    receiver = func.value
    if _chain_has_db_call(receiver, ctx):
        return True
    # handle = sqlite3.connect(...); handle.execute(...)
    if isinstance(receiver, ast.Name) and any(
        _chain_has_db_call(value, ctx) for value in ctx.binding_values(receiver.id, func)
    ):
        return True
    last = receiver
    if isinstance(last, ast.Call):
        last = last.func
    ident = last.attr if isinstance(last, ast.Attribute) else getattr(last, "id", "")
    return bool(_DB_NAME_RE.search(ident))


def _chain_has_db_call(expr: ast.AST, ctx: FileContext) -> bool:
    """sqlite3.connect(...).execute(...), psycopg.connect(...).cursor().execute(...)"""
    while isinstance(expr, (ast.Call, ast.Attribute)):
        if isinstance(expr, ast.Call):
            if any(_in_db_module(n) for n in ctx.call_names(expr)):
                return True
            expr = expr.func
        else:
            expr = expr.value
    return False


def _in_db_module(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in DB_MODULES)


def _short(text: str, limit: int = 40) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
