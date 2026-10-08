from __future__ import annotations

from typing import Any

import pytest

from hackscan.core.models import Finding, Region, Severity
from hackscan.core.taxonomy import classify


def _make_finding(
    *,
    rule_id: str = "HS-SQLI-001",
    path: str = "app/db.py",
    line: int = 10,
    end_line: int | None = None,
    snippet: str = 'cursor.execute(f"SELECT * FROM t WHERE id={uid}")',
    function: str | None = "get_user",
    sources: tuple[str, ...] = ("hackscan",),
    cwe: tuple[str, ...] = ("CWE-89",),
    severity: Severity = Severity.HIGH,
    **kwargs: Any,
) -> Finding:
    return Finding(
        id="",
        vuln_class=kwargs.pop("vuln_class", None) or classify(rule_id, cwe),
        rule_id=rule_id,
        severity=severity,
        location=Region(path=path, start_line=line, end_line=end_line),
        message=kwargs.pop("message", "test finding"),
        snippet=snippet,
        function=function,
        sources=sources,
        cwe=cwe,
        **kwargs,
    )


@pytest.fixture
def make_finding():
    return _make_finding
