"""Sanitizers: calls whose result is safe for some (or all) injection classes."""

from __future__ import annotations

from hackscan.core.taxonomy import CMDI, SQLI, TAINT_CLASSES

ALL = TAINT_CLASSES

# Fully-qualified call name -> vuln classes the result is safe for.
SANITIZERS: dict[str, frozenset[str]] = {
    # Numeric / boolean / identifier conversions cannot carry injection payloads. (Not
    # `abs`/`round`: `__abs__`/`__round__` may return anything; they pass credit through.)
    "int": ALL,
    "float": ALL,
    "bool": ALL,
    "len": ALL,
    "builtins.int": ALL,
    "builtins.float": ALL,
    "uuid.UUID": ALL,
    "decimal.Decimal": ALL,
    # Shell quoting. Context-sensitive: see QUOTING_SANITIZERS.
    "shlex.quote": frozenset({CMDI}),
    "shlex.join": frozenset({CMDI}),
    "pipes.quote": frozenset({CMDI}),
    # SQL identifier/literal quoting helpers.
    "psycopg2.sql.Identifier": frozenset({SQLI}),
    "psycopg2.sql.Literal": frozenset({SQLI}),
    "psycopg.sql.Identifier": frozenset({SQLI}),
    "psycopg.sql.Literal": frozenset({SQLI}),
}

# Sanitizers whose result is a number (rendered as digits, sign, `.`, `e`, inf/nan).
NUMERIC_SANITIZERS = frozenset(
    {
        "int",
        "float",
        "bool",
        "len",
        "builtins.int",
        "builtins.float",
        "decimal.Decimal",
    }
)

# SQL objects: safe when the driver receives the object itself, which quotes it on
# execution. Their Python text (`str()`, f-strings, `%`) is not SQL-quoted, and their
# attributes (`.wrapped`, `.strings`) are the raw data, so the credit holds only while the
# object is passed on as is (see taint_pass `_keeps_object`).
SQL_OBJECT_SANITIZERS = frozenset(
    {
        "psycopg2.sql.Identifier",
        "psycopg2.sql.Literal",
        "psycopg.sql.Identifier",
        "psycopg.sql.Literal",
    }
)

# Sanitizers whose safety depends on where the result is placed: a shell-quoted value
# embedded inside another quote context (`'echo "' + shlex.quote(x) + '"'`) is unsafe.
# Note: `ast.literal_eval` is deliberately absent: it can return a string, which is
# still dangerous when passed on to eval/exec.
QUOTING_SANITIZERS = frozenset({"shlex.quote", "shlex.join", "pipes.quote"})


# Programs whose arguments are data: no option or operand runs a command, loads code or
# writes an arbitrary file. An argument list only makes a dynamic value safe for these;
# countless others execute operands or options (`sh -c`, `npx PKG`, `git -c alias=!cmd`,
# `tar --to-command`, `sort --compress-program`, `find -exec`, `rg --pre`), so an
# allowlist, not a denylist.
INERT_PROGRAMS = {
    "printf", "cat", "tac", "nl", "ls", "head", "tail", "wc", "cut",
    "grep", "egrep", "fgrep", "file", "stat", "du", "df", "basename", "dirname",
    "realpath", "readlink", "which", "whoami", "id", "ping", "host", "dig", "nslookup",
}  # fmt: skip


def program_name(literal: str) -> str:
    """`/bin/grep` or `C:\\Tools\\grep.exe` -> `grep`. Only `.exe` is dropped: `.bat` and
    `.cmd` files run through cmd.exe, which re-parses the arguments."""
    name = literal.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[: -len(".exe")] if name.endswith(".exe") else name
