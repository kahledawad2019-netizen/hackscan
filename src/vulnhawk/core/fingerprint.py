"""Stable, vendor-independent finding ids.

id = H(vuln_class, path, enclosing function, normalized sink expression)

The sink expression comes from `Finding.sink` (text taken from the source file), falling
back to `snippet` only when no sink was recorded. Line numbers are deliberately excluded
so ids survive unrelated edits that shift code.
Identical sinks in the same function are disambiguated by occurrence order.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace

from vulnhawk.core.models import Finding

ID_PREFIX = "vh1-"  # bump if the fingerprint recipe changes
_HEX_LEN = 32
_WS_RE = re.compile(r"\s+")


def normalize_expression(code: str) -> str:
    """Canonical form of a code snippet: formatting- and comment-insensitive when parseable."""
    text = code.strip()
    if not text:
        return ""
    for mode in ("eval", "exec"):
        try:
            return ast.unparse(ast.parse(text, mode=mode))
        except SyntaxError:
            continue
    return _WS_RE.sub(" ", text)


def compute_fingerprint(
    vuln_class: str, path: str, function: str | None, sink_expression: str, occurrence: int = 0
) -> str:
    parts = [vuln_class, path, function or "<module>", normalize_expression(sink_expression)]
    if occurrence:
        parts.append(f"#{occurrence}")
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return ID_PREFIX + digest[:_HEX_LEN]


def assign_ids(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings with `id` set. Input order does not affect the result."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        base = compute_fingerprint(f.vuln_class, f.location.path, f.function, sink_text(f))
        groups[base].append(f)

    result: list[Finding] = []
    for base, members in groups.items():
        members.sort(key=lambda f: (*f.location.sort_key(), f.canonical_json()))
        for occurrence, f in enumerate(members):
            new_id = (
                base
                if occurrence == 0
                else compute_fingerprint(
                    f.vuln_class, f.location.path, f.function, sink_text(f), occurrence
                )
            )
            result.append(replace(f, id=new_id))
    result.sort(key=Finding.sort_key)
    return result


def sink_text(f: Finding) -> str:
    return f.sink or f.snippet
