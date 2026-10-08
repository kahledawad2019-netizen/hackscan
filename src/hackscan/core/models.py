"""Finding schema v1. Frozen at M0: changes require bumping SCHEMA_VERSION.

Every pass and importer produces or transforms `Finding` objects. Passes never delete
findings; they return updated copies (see `dataclasses.replace`).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Any

SCHEMA_VERSION = 1

OWN_SOURCE = "hackscan"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class Status(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    SUPPRESSED = "suppressed"

    @property
    def rank(self) -> int:
        """Merge precedence: confirmed > candidate > suppressed."""
        return _STATUS_RANK[self]


_STATUS_RANK = {Status.SUPPRESSED: 0, Status.CANDIDATE: 1, Status.CONFIRMED: 2}


@dataclass(frozen=True)
class Region:
    """Source location. Lines and columns are 1-based (SARIF convention).

    `path` is a POSIX path relative to the scan root. `end_column` is exclusive (SARIF
    `endColumn`); None means "to end of line".
    """

    path: str
    start_line: int
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.start_column < 1:
            raise ValueError(f"Region lines/columns are 1-based: {self}")
        if "\\" in self.path:
            raise ValueError(f"Region path must be POSIX-style: {self.path!r}")
        if self.end_line is None:
            object.__setattr__(self, "end_line", self.start_line)
        if self.end_line < self.start_line:
            raise ValueError(f"Region ends before it starts: {self}")
        if self.end_column is not None and (
            self.end_column < 1
            or (self.end_line == self.start_line and self.end_column < self.start_column)
        ):
            raise ValueError(f"Region end column is invalid: {self}")

    @property
    def start_pos(self) -> tuple[int, float]:
        return (self.start_line, self.start_column)

    @property
    def end_pos(self) -> tuple[int, float]:
        """Exclusive end position; whole-line when `end_column` is None."""
        if self.end_column is None:
            return (self.end_line, math.inf)
        # Zero-width regions still cover the character they point at.
        if self.end_line == self.start_line and self.end_column == self.start_column:
            return (self.end_line, self.end_column + 1)
        return (self.end_line, self.end_column)

    @property
    def span(self) -> tuple[int, float]:
        """Ordering heuristic preferring precise regions: (extra lines, column delta).

        Only used to pick visit order; correctness of dedupe does not depend on it.
        """
        return (self.end_line - self.start_line, self.end_pos[1] - self.start_column)

    def overlaps(self, other: Region) -> bool:
        """Position overlap (line and column aware) within the same file."""
        return (
            self.path == other.path
            and self.start_pos < other.end_pos
            and other.start_pos < self.end_pos
        )

    def sort_key(self) -> tuple[str, int, int]:
        return (self.path, self.start_line, self.start_column)


@dataclass(frozen=True)
class Evidence:
    """One piece of supporting evidence, tagged with the producer (pass or tool)."""

    producer: str
    kind: str  # e.g. "taint_step", "tool_message", "llm_rationale"
    message: str
    region: Region | None = None


@dataclass(frozen=True)
class FixEdit:
    region: Region
    replacement: str


@dataclass(frozen=True)
class Fix:
    description: str
    edits: tuple[FixEdit, ...]
    producer: str


@dataclass(frozen=True)
class Finding:
    id: str
    vuln_class: str
    rule_id: str
    severity: Severity
    location: Region
    message: str
    snippet: str = ""
    cwe: tuple[str, ...] = ()
    related_rules: tuple[str, ...] = ()
    sources: tuple[str, ...] = (OWN_SOURCE,)
    status: Status = Status.CANDIDATE
    suppression: str | None = None
    confidence: int = 50
    evidence: tuple[Evidence, ...] = ()
    fix: Fix | None = None
    # Enclosing function qualname. Like `sink`, producers derive it from the parsed file
    # (importers look it up by location), so it does not depend on which tool reported.
    function: str | None = None
    # Source text of the sink expression at `location`, used for fingerprinting.
    # Producers set it from the parsed file (own engine: the sink AST node; importers:
    # the file text covered by the region), never from a tool-provided display snippet.
    sink: str = ""

    def __post_init__(self) -> None:
        if not 0 <= self.confidence <= 100:
            raise ValueError(f"confidence must be 0-100, got {self.confidence}")
        if (self.status is Status.SUPPRESSED) != (self.suppression is not None):
            raise ValueError("suppression reason is required iff status is suppressed")

    def sort_key(self) -> tuple[str, int, int, str, str, str]:
        """Deterministic output ordering: path, line, column, rule, id, then full content."""
        return (*self.location.sort_key(), self.rule_id, self.id, self.canonical_json())

    def canonical_json(self) -> str:
        """Stable serialization; a total-order tie-breaker for equal-looking findings."""
        return self._canonical_json

    @cached_property
    def _canonical_json(self) -> str:
        # Safe to cache: Finding is frozen, and cached_property writes to __dict__
        # directly (not a dataclass field, so eq/hash/replace are unaffected).
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "id": self.id,
            "vuln_class": self.vuln_class,
            "rule_id": self.rule_id,
            "related_rules": list(self.related_rules),
            "cwe": list(self.cwe),
            "severity": self.severity.value,
            "confidence": self.confidence,
            "status": self.status.value,
            "suppression": self.suppression,
            "sources": list(self.sources),
            "message": self.message,
            "location": _region_to_dict(self.location),
            "function": self.function,
            "sink": self.sink,
            "snippet": self.snippet,
            "evidence": [
                {
                    "producer": e.producer,
                    "kind": e.kind,
                    "message": e.message,
                    "region": _region_to_dict(e.region) if e.region else None,
                }
                for e in self.evidence
            ],
            "fix": None
            if self.fix is None
            else {
                "description": self.fix.description,
                "producer": self.fix.producer,
                "edits": [
                    {"region": _region_to_dict(ed.region), "replacement": ed.replacement}
                    for ed in self.fix.edits
                ],
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        version = data.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(f"unsupported Finding schema_version {version!r}")
        fix = data.get("fix")
        return cls(
            id=data["id"],
            vuln_class=data["vuln_class"],
            rule_id=data["rule_id"],
            related_rules=tuple(data.get("related_rules", ())),
            cwe=tuple(data.get("cwe", ())),
            severity=Severity(data["severity"]),
            confidence=data["confidence"],
            status=Status(data["status"]),
            suppression=data.get("suppression"),
            sources=tuple(data["sources"]),
            message=data["message"],
            location=Region(**data["location"]),
            function=data.get("function"),
            sink=data.get("sink", ""),
            snippet=data.get("snippet", ""),
            evidence=tuple(
                Evidence(
                    producer=e["producer"],
                    kind=e["kind"],
                    message=e["message"],
                    region=Region(**e["region"]) if e.get("region") else None,
                )
                for e in data.get("evidence", ())
            ),
            fix=None
            if fix is None
            else Fix(
                description=fix["description"],
                producer=fix["producer"],
                edits=tuple(
                    FixEdit(region=Region(**ed["region"]), replacement=ed["replacement"])
                    for ed in fix["edits"]
                ),
            ),
        )


def _region_to_dict(region: Region) -> dict[str, Any]:
    return {
        "path": region.path,
        "start_line": region.start_line,
        "start_column": region.start_column,
        "end_line": region.end_line,
        "end_column": region.end_column,
    }
