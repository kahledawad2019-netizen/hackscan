"""Sanitizers: calls whose result is safe for some (or all) injection classes."""

from __future__ import annotations

from hackscan.core.taxonomy import CMDI, SQLI, TAINT_CLASSES

ALL = TAINT_CLASSES

# Fully-qualified call name -> vuln classes the result is safe for.
SANITIZERS: dict[str, frozenset[str]] = {
    # Numeric / boolean / identifier conversions cannot carry injection payloads.
    "int": ALL,
    "float": ALL,
    "bool": ALL,
    "abs": ALL,
    "len": ALL,
    "round": ALL,
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

# Sanitizers whose safety depends on where the result is placed: a shell-quoted value
# embedded inside another quote context (`'echo "' + shlex.quote(x) + '"'`) is unsafe.
# Note: `ast.literal_eval` is deliberately absent: it can return a string, which is
# still dangerous when passed on to eval/exec.
QUOTING_SANITIZERS = frozenset({"shlex.quote", "shlex.join", "pipes.quote"})
