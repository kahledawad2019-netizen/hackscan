"""Secret redaction for every user-facing field of a finding.

Applied after merging, before ids are assigned, so no output format (text, JSON, SARIF)
can carry a secret regardless of which tool reported it or which contributor became the
primary of a merged finding.

- Known secret values (e.g. Gitleaks `Secret`) are replaced wherever they appear.
- For findings of class `secret` from any tool, every quoted string literal in the
  snippet, sink, message and evidence is replaced as well (Bandit's B105 message, for
  instance, quotes the password it found).
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


def redact_text(text: str, secrets: Iterable[str], literals: bool) -> str:
    for secret in sorted(set(secrets), key=len, reverse=True):
        if len(secret) >= MIN_SECRET_LENGTH:
            text = text.replace(secret, REDACTED)
    if literals:
        text = _LITERAL_RE.sub(lambda m: f"{m.group('q')}{REDACTED}{m.group('q')}", text)
    return text


def redact_findings(findings: list[Finding], secrets: Iterable[str]) -> list[Finding]:
    secrets = [s for s in set(secrets) if len(s) >= MIN_SECRET_LENGTH]
    out = []
    for f in findings:
        literals = f.vuln_class == SECRET

        def clean(text: str, literals: bool = literals) -> str:
            return redact_text(text, secrets, literals)

        new = replace(
            f,
            message=clean(f.message),
            snippet=clean(f.snippet),
            sink=clean(f.sink),
            evidence=tuple(replace(e, message=clean(e.message)) for e in f.evidence),
        )
        out.append(new if new != f else f)
    return out
