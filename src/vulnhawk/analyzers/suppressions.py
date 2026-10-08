"""Inline suppressions: `# vulnhawk: ignore` or `# vulnhawk: ignore[RULE, ...]`.

The comment may sit on any line of the finding's region (start line for single-line
calls, closing line for multi-line ones). Suppressed findings are kept, with
`suppression = "inline:vulnhawk-ignore"`.
"""

from __future__ import annotations

import io
import re
import tokenize
from dataclasses import replace

from vulnhawk.core.models import Evidence, Finding, Status
from vulnhawk.plugins.base import FileContext

INLINE = "inline:vulnhawk-ignore"
_DIRECTIVE_RE = re.compile(r"#\s*vulnhawk:\s*ignore(?:\[(?P<rules>[^\]]*)\])?", re.IGNORECASE)


def directives(source: str) -> dict[int, frozenset[str] | None]:
    """Line -> rule ids to ignore (None = all rules). Only real comments count."""
    out: dict[int, frozenset[str] | None] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for tok in tokens:
            if tok.type != tokenize.COMMENT:
                continue
            match = _DIRECTIVE_RE.search(tok.string)
            if not match:
                continue
            rules = match.group("rules")
            line = tok.start[0]
            if rules is None:
                out[line] = None
            elif out.get(line, frozenset()) is not None:
                parsed = frozenset(r.strip() for r in rules.split(",") if r.strip())
                out[line] = (out.get(line) or frozenset()) | parsed
    except (tokenize.TokenError, SyntaxError):
        pass  # unparseable files have no findings anyway
    return out


def apply_inline_suppressions(findings: list[Finding], ctx: FileContext) -> list[Finding]:
    marks = directives(ctx.source)
    if not marks:
        return findings
    out = []
    for f in findings:
        lines = range(f.location.start_line, f.location.end_line + 1)
        hit = any(
            line in marks and (marks[line] is None or f.rule_id in marks[line]) for line in lines
        )
        if hit and f.status is not Status.SUPPRESSED:
            f = replace(
                f,
                status=Status.SUPPRESSED,
                suppression=INLINE,
                evidence=(*f.evidence, Evidence("inline", "suppression", "Ignored by comment.")),
            )
        out.append(f)
    return out
