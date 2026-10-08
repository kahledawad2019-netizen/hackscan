"""Sanitizers: calls whose result is safe for some (or all) injection classes."""

from __future__ import annotations

from vulnhawk.core.taxonomy import CMDI, CODEI, SQLI, TAINT_CLASSES

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
    # Shell quoting.
    "shlex.quote": frozenset({CMDI}),
    "pipes.quote": frozenset({CMDI}),
    # Parses literals only; never executes code.
    "ast.literal_eval": frozenset({CODEI}),
    # SQL identifier/literal quoting helpers.
    "psycopg2.sql.Identifier": frozenset({SQLI}),
    "psycopg2.sql.Literal": frozenset({SQLI}),
    "psycopg.sql.Identifier": frozenset({SQLI}),
    "psycopg.sql.Literal": frozenset({SQLI}),
}
