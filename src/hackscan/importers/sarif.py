"""SARIF 2.1.0 import (Semgrep, Bandit, CodeQL, or any SARIF producer)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hackscan.core.models import Evidence, Finding, Severity
from hackscan.core.taxonomy import classify, normalize_cwes
from hackscan.importers.common import (
    SEVERITY_FROM_LEVEL,
    ImportResult,
    ReportError,
    SourceIndex,
    make_region,
    normalize_path,
    severity_from_score,
)

# Tool driver names -> source label used in findings.
KNOWN_DRIVERS = {
    "semgrep": "semgrep",
    "semgrep oss": "semgrep",
    "semgrep pro": "semgrep",
    "bandit": "bandit",
    "codeql": "codeql",
}
DEFAULT_CONFIDENCE = {"semgrep": 60, "bandit": 60, "codeql": 75}
BANDIT_CONFIDENCE = {"HIGH": 80, "MEDIUM": 60, "LOW": 40}
BANDIT_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def load_sarif(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"{path}: not a readable SARIF/JSON file: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise ReportError(f"{path}: not a SARIF log (missing `runs`)")
    return data


def import_sarif(
    data: dict[str, Any], root: Path, index: SourceIndex, label: str | None = None
) -> ImportResult:
    """Convert every result of every run. `label` forces the source label."""
    result = ImportResult(tool=label or "sarif")
    for run in data.get("runs", []):
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {}) or {}
        source = label or KNOWN_DRIVERS.get(str(driver.get("name", "")).lower(), "sarif")
        result.tool = source
        rules = _rules_by_id(driver)
        base_uris = {
            k: v.get("uri")
            for k, v in (run.get("originalUriBaseIds") or {}).items()
            if isinstance(v, dict)
        }
        for raw in run.get("results", []) or []:
            try:
                finding = _convert(raw, source, rules, base_uris, root, index, result.warnings)
            except (AttributeError, KeyError, TypeError, ValueError) as exc:
                result.warnings.append(f"{source}: skipped malformed result: {exc}")
                continue
            if finding is not None:
                result.findings.append(finding)
    return result


def _rules_by_id(driver: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = {}
    for rule in driver.get("rules", []) or []:
        if isinstance(rule, dict) and rule.get("id"):
            rules[str(rule["id"])] = rule
    return rules


def _convert(
    raw: dict[str, Any],
    source: str,
    rules: dict[str, dict[str, Any]],
    base_uris: dict[str, str | None],
    root: Path,
    index: SourceIndex,
    warn: list[str],
) -> Finding | None:
    rule_key = str(raw.get("ruleId") or raw.get("rule", {}).get("id") or "unknown")
    rule = rules.get(rule_key, {})
    locations = raw.get("locations") or []
    if not locations:
        warn.append(f"{source}: result for {rule_key} has no location; skipped")
        return None
    physical = locations[0].get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    uri = artifact.get("uri")
    if not uri:
        warn.append(f"{source}: result for {rule_key} has no file; skipped")
        return None
    rel = normalize_path(uri, root, base_uris.get(artifact.get("uriBaseId", "")))
    if rel is None:
        warn.append(f"{source}: {uri} is outside the scan root; skipped")
        return None
    reg = physical.get("region", {}) or {}
    region = make_region(
        rel,
        reg.get("startLine"),
        reg.get("startColumn"),
        reg.get("endLine"),
        reg.get("endColumn"),
    )

    props = {**(rule.get("properties") or {}), **(raw.get("properties") or {})}
    cwes = normalize_cwes([*_strings(props.get("tags")), *_strings(props.get("cwe"))])
    rule_id = f"{source}:{rule_key}"
    severity, confidence = _severity_confidence(raw, rule, props, source)
    message = (raw.get("message") or {}).get("text") or rule.get("shortDescription", {}).get(
        "text", rule_key
    )
    # Only parsed source has a trustworthy masked snippet.
    snippet = index.line_text(rel, region.start_line)
    sink, function = index.enrich(region)
    return Finding(
        id="",
        vuln_class=classify(rule_id, cwes),
        rule_id=rule_id,
        severity=severity,
        location=region,
        message=str(message).strip(),
        snippet=str(snippet).rstrip("\n"),
        sink=sink,
        function=function,
        cwe=cwes,
        sources=(source,),
        confidence=confidence,
        evidence=(Evidence(source, "tool_message", str(message).strip()),),
    )


def _severity_confidence(
    raw: dict[str, Any], rule: dict[str, Any], props: dict[str, Any], source: str
) -> tuple[Severity, int]:
    confidence = DEFAULT_CONFIDENCE.get(source, 50)
    score = props.get("security-severity")
    if source == "bandit":
        severity = BANDIT_SEVERITY.get(str(props.get("issue_severity", "")).upper())
        confidence = BANDIT_CONFIDENCE.get(str(props.get("issue_confidence", "")).upper(), 60)
        if severity is not None:
            return severity, confidence
    if score is not None:
        try:
            return severity_from_score(float(score)), confidence
        except (TypeError, ValueError):
            pass
    level = raw.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return SEVERITY_FROM_LEVEL.get(str(level), Severity.MEDIUM), confidence


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []
