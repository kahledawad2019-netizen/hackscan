"""SARIF 2.1.0 export (validated against the OASIS schema in tests).

- One run, tool driver `HackScan` with a `reportingDescriptor` per rule that occurs.
- Every finding is emitted, including suppressed ones (with `suppressions[]`), so code
  scanning platforms can show them as dismissed rather than losing them.
- `partialFingerprints["hackscan/v1"]` carries the stable finding id.
- Columns are Unicode code points (`columnKind`), matching the engine's char columns.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hackscan import __version__
from hackscan.core.models import Finding, Severity, Status
from hackscan.core.pipeline import ScanResult
from hackscan.plugins.base import RulePlugin

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://pypi.org/project/hackscan/"
FINGERPRINT_KEY = "hackscan/v1"
SRCROOT = "%SRCROOT%"

LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# GitHub code scanning reads `security-severity` (CVSS-like) to bucket alerts.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def export_sarif(result: ScanResult, plugins: Iterable[RulePlugin] = ()) -> dict[str, Any]:
    by_id = {p.rule_id: p for p in plugins}
    findings = sorted(result.findings, key=Finding.sort_key)
    rule_ids = sorted({f.rule_id for f in findings})
    rule_index = {rule_id: i for i, rule_id in enumerate(rule_ids)}
    rules = [_rule(rule_id, by_id.get(rule_id), findings) for rule_id in rule_ids]
    notifications = [{"level": "error", "message": {"text": e}} for e in result.errors] + [
        {"level": "warning", "message": {"text": w}} for w in result.warnings
    ]
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "HackScan",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {SRCROOT: {"uri": result.root.resolve().as_uri() + "/"}},
                "columnKind": "unicodeCodePoints",
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": [_result(f, rule_index[f.rule_id]) for f in findings],
            }
        ],
    }


def _rule(rule_id: str, plugin: RulePlugin | None, findings: list[Finding]) -> dict[str, Any]:
    sample = next(f for f in findings if f.rule_id == rule_id)
    severity = plugin.severity if plugin is not None else sample.severity
    cwes = plugin.cwe if plugin is not None else sample.cwe
    name = plugin.name if plugin is not None else rule_id.split(":", 1)[-1]
    description = plugin.description if plugin is not None else sample.message
    tags = ["security", *(f"external/cwe/{c.lower()}" for c in cwes)]
    return {
        "id": rule_id,
        "name": _pascal(name),
        "shortDescription": {"text": description[:200]},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": LEVEL[severity]},
        "help": {"text": f"{description} Vulnerability class: {sample.vuln_class}."},
        "properties": {
            "tags": tags,
            "security-severity": SECURITY_SEVERITY[severity],
            "precision": "high" if plugin is not None else "medium",
        },
    }


def _result(f: Finding, index: int) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": index,
        "level": LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [{"physicalLocation": _physical(f)}],
        "partialFingerprints": {FINGERPRINT_KEY: f.id},
        "properties": {
            "severity": f.severity.value,
            "security-severity": SECURITY_SEVERITY[f.severity],
            "confidence": f.confidence,
            "status": f.status.value,
            "vulnClass": f.vuln_class,
            "cwe": list(f.cwe),
            "sources": list(f.sources),
            "relatedRules": list(f.related_rules),
            "function": f.function,
            "evidence": [
                {"producer": e.producer, "kind": e.kind, "message": e.message} for e in f.evidence
            ],
        },
    }
    if f.status is Status.SUPPRESSED:
        out["suppressions"] = [
            {
                "kind": "inSource" if (f.suppression or "").startswith("inline:") else "external",
                "status": "accepted",
                "justification": f.suppression or "",
            }
        ]
    if f.fix is not None:
        out["fixes"] = [
            {
                "description": {"text": f.fix.description},
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": f.location.path, "uriBaseId": SRCROOT},
                        "replacements": [
                            {
                                "deletedRegion": _region(edit.region),
                                "insertedContent": {"text": edit.replacement},
                            }
                            for edit in f.fix.edits
                        ],
                    }
                ],
            }
        ]
    return out


def _physical(f: Finding) -> dict[str, Any]:
    region = _region(f.location)
    if f.snippet:
        region["snippet"] = {"text": f.snippet}
    return {
        "artifactLocation": {"uri": f.location.path, "uriBaseId": SRCROOT},
        "region": region,
    }


def _region(r) -> dict[str, Any]:
    region: dict[str, Any] = {
        "startLine": r.start_line,
        "startColumn": r.start_column,
        "endLine": r.end_line,
    }
    if r.end_column is not None:
        region["endColumn"] = r.end_column
    return region


def _pascal(name: str) -> str:
    parts = [p for p in name.replace("_", "-").replace(".", "-").replace("/", "-").split("-") if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Rule"
