"""Secret redaction for every user-facing field of a finding.

Applied after merging, before ids are assigned, so no output format (text, JSON, SARIF)
can carry a secret regardless of which tool reported it or which contributor became the
primary of a merged finding.

- Known secret values (e.g. Gitleaks `Secret`) are replaced wherever they appear.
- Findings of class `secret` never carry tool-provided text: their message and evidence
  become generic, and in snippet/sink every string literal and every assigned value
  (`token = abc`, `password: abc`) is replaced. A tool may describe a secret in any
  form (quoted, unquoted, inside a message), so content-based redaction is not enough.
- `redact_messages` applies known-secret replacement to warnings and errors too.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import replace

from hackscan.core.models import Finding
from hackscan.core.taxonomy import SECRET

REDACTED = "<REDACTED>"
MIN_SECRET_LENGTH = 4  # shorter "secrets" would redact ordinary text
_LITERAL_RE = re.compile(r"""(?P<q>['"])(?:\\.|(?!(?P=q)).)+(?P=q)""")
# `key = value` / `key: value` / `key=value` (value up to end of line or comment).
_ASSIGNED_RE = re.compile(r"(?P<key>[=:]\s*)(?P<value>[^\s#'\"][^#]*?)(?P<tail>\s*(?:#.*)?)$")


def redact_text(text: str, secrets: Iterable[str], literals: bool) -> str:
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) >= MIN_SECRET_LENGTH:
            text = text.replace(secret, REDACTED)
    if literals:
        text = _LITERAL_RE.sub(lambda m: f"{m.group('q')}{REDACTED}{m.group('q')}", text)
    return text


def redact_code(text: str, secrets: Iterable[str]) -> str:
    """Secret-class snippet/sink: literals and assigned values removed, line by line."""
    lines = []
    for line in redact_text(text, secrets, literals=True).split("\n"):
        lines.append(
            _ASSIGNED_RE.sub(lambda m: f"{m.group('key')}{REDACTED}{m.group('tail')}", line)
        )
    return "\n".join(lines)


def redact_messages(messages: Iterable[str], secrets: Iterable[str]) -> list[str]:
    secrets = list(secrets)
    return [redact_text(m, secrets, literals=False) for m in messages]


SECRET_NAME_RE = re.compile(r"(key|token|secret|passw|pwd|credential|auth)", re.I)
_ASSIGN_LITERAL_RE = re.compile(
    r"""(?P<name>[A-Za-z_][\w.]*)\s*[:=]\s*(?P<q>['"])(?P<value>(?:\\.|(?!(?P=q)).)*)(?P=q)"""
)
_LONG_LITERAL_RE = re.compile(r"""(['"])([A-Za-z0-9+/=_\-]{20,})\1""")
# C0/C1 control characters except tab and newline: never let scanned code, tool output or
# model text drive the terminal (clear screen, cursor moves, fake lines).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_controls(text: str) -> str:
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


def _entropy(text: str) -> float:
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def redact_secretish(text: str, secrets: Iterable[str] = ()) -> str:
    """Known secrets, literals assigned to secret-looking names, and long high-entropy
    literals, for text that leaves the scanner in raw form (LLM context, diffs)."""
    text = redact_text(text, secrets, literals=False)

    def assigned(m: re.Match) -> str:
        if SECRET_NAME_RE.search(m.group("name")):
            return f"{m.group('name')} = {m.group('q')}{REDACTED}{m.group('q')}"
        return m.group(0)

    text = _ASSIGN_LITERAL_RE.sub(assigned, text)
    return _LONG_LITERAL_RE.sub(
        lambda m: (
            m.group(0) if _entropy(m.group(2)) < 3.5 else f"{m.group(1)}{REDACTED}{m.group(1)}"
        ),
        text,
    )


def redact_findings(findings: list[Finding], secrets: Iterable[str]) -> list[Finding]:
    secrets = [s for s in set(secrets) if len(s) >= MIN_SECRET_LENGTH]
    out = []
    for f in findings:
        if f.vuln_class == SECRET:
            generic = f"Possible hard-coded secret reported by {', '.join(f.sources)}."
            new = replace(
                f,
                message=generic,
                snippet=redact_code(f.snippet, secrets),
                sink=redact_code(f.sink, secrets),
                evidence=tuple(
                    replace(e, message=f"{e.producer} reported a secret ({f.rule_id}).")
                    for e in f.evidence
                ),
            )
        else:

            def clean(text: str) -> str:
                return redact_text(text, secrets, literals=False)

            new = replace(
                f,
                message=clean(f.message),
                snippet=clean(f.snippet),
                sink=clean(f.sink),
                evidence=tuple(replace(e, message=clean(e.message)) for e in f.evidence),
                fix=_clean_fix(f.fix, clean),
            )
        out.append(new if new != f else f)
    return out


def _clean_fix(fix, clean):
    if fix is None:
        return None
    edits = tuple(replace(e, replacement=clean(e.replacement)) for e in fix.edits)
    return replace(fix, description=clean(fix.description), edits=edits)
