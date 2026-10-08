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
            )
        out.append(new if new != f else f)
    return out
