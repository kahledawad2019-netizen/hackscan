"""Gitleaks JSON report import (`gitleaks detect --report-format json`).

Secrets are never copied into findings: the matched text is redacted in the snippet and
the secret value itself is dropped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hackscan.core.models import Evidence, Finding, Severity
from hackscan.core.taxonomy import SECRET
from hackscan.importers.common import (
    ImportResult,
    ReportError,
    SourceIndex,
    make_region,
    normalize_path,
)

REDACTED = "<REDACTED>"
SOURCE = "gitleaks"


def load_gitleaks(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8-sig").strip()
        data = json.loads(text) if text else []
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"{path}: not a readable Gitleaks JSON report: {exc}") from exc
    if not isinstance(data, list):
        raise ReportError(f"{path}: Gitleaks report must be a JSON array")
    return data


def import_gitleaks(items: list[dict[str, Any]], root: Path, index: SourceIndex) -> ImportResult:
    result = ImportResult(tool=SOURCE)
    for item in items:
        if not isinstance(item, dict):
            result.warnings.append("gitleaks: skipped non-object entry")
            continue
        raw_path = item.get("File") or item.get("file")
        if not raw_path:
            result.warnings.append("gitleaks: skipped entry without File")
            continue
        rel = normalize_path(str(raw_path), root)
        if rel is None:
            result.warnings.append(f"gitleaks: {raw_path} is outside the scan root; skipped")
            continue
        region = make_region(
            rel,
            item.get("StartLine"),
            item.get("StartColumn"),
            item.get("EndLine"),
            # Gitleaks columns are inclusive; SARIF/Region end columns are exclusive.
            (item.get("EndColumn") or 0) + 1 if item.get("EndColumn") else None,
        )
        secret = str(item.get("Secret") or "")
        rule = str(item.get("RuleID") or "generic")
        description = str(item.get("Description") or f"Secret detected ({rule})")
        line = index.line_text(rel, region.start_line)
        snippet = _redact(line or str(item.get("Match") or ""), secret)
        result.findings.append(
            Finding(
                id="",
                vuln_class=SECRET,
                rule_id=f"{SOURCE}:{rule}",
                severity=Severity.HIGH,
                location=region,
                message=description,
                snippet=snippet,
                # A secret's identity is its location and rule, never its value.
                sink=f"{rule}@{rel}:{region.start_line}",
                function=None,
                cwe=("CWE-798",),
                sources=(SOURCE,),
                confidence=70,
                evidence=(Evidence(SOURCE, "tool_message", description),),
            )
        )
    return result


def _redact(text: str, secret: str) -> str:
    if secret and secret in text:
        return text.replace(secret, REDACTED)
    return text if not secret else REDACTED
