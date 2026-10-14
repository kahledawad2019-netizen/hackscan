"""Security knowledge as data: untrusted-input sources (and, later, ranking vocabulary).

The built-in entries ship in `knowledge.json` next to this module. Every entry carries its
provenance, assigned here by the loader and never read from the data: "built-in" for the packaged
file, "project note" for entries from a project's `.hackscan.yml` (`knowledge:` section). Project
entries can only add knowledge of the types in PROJECT_TYPES; they can never remove a built-in
entry, and there is no entry type for sanitizers or suppressions.

One Knowledge object is active per scan: a context variable set by the pipeline for the scan's
duration (so concurrent scans in one process stay isolated) and in each worker process.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

SCHEMA = "hackscan-knowledge/1"
BUILT_IN = "built-in"
PROJECT_NOTE = "project note"
TYPES = ("flask_request_attr", "request_param_attr", "request_param_name", "source_name", "route_decorator")
PROJECT_TYPES = frozenset(TYPES)  # every current type only ADDS untrusted input
ENTRY_KEYS = {"type", "value", "description", "rationale", "evidence"}


class KnowledgeError(ValueError):
    """Malformed knowledge data."""


@dataclass(frozen=True)
class Knowledge:
    flask_request_attrs: frozenset[str]
    request_param_attrs: frozenset[str]
    request_param_names: frozenset[str]
    source_names: dict[str, str]  # resolved dotted name -> description
    route_decorators: frozenset[str]
    version: str
    sha256: str  # of the packaged built-in file
    provenance: dict[tuple[str, str], str] = field(default_factory=dict, compare=False)  # (type, value) -> origin
    # (type, value) -> {"rationale": ..., "evidence": ...}, kept for every entry that was added
    details: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict, compare=False)

    def with_entries(self, entries: list[dict[str, Any]], origin: str = PROJECT_NOTE) -> Knowledge:
        """A copy with project entries added (never removing anything)."""
        if origin == BUILT_IN:
            raise KnowledgeError("project entries cannot claim built-in provenance")
        parsed = [_entry(e, allowed=PROJECT_TYPES, where=f"{origin} {i + 1}") for i, e in enumerate(entries)]
        return _build(parsed, origin, base=self)


def _entry(raw: Any, *, allowed: frozenset[str], where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise KnowledgeError(f"{where}: an entry must be a mapping")
    unknown = set(raw) - ENTRY_KEYS
    if unknown:
        raise KnowledgeError(f"{where}: unknown key(s) {sorted(map(repr, unknown))}")
    kind, value = raw.get("type"), raw.get("value")
    if not isinstance(kind, str) or kind not in allowed:
        raise KnowledgeError(f"{where}: type must be one of {sorted(allowed)}")
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise KnowledgeError(f"{where}: value must be a non-empty string without surrounding spaces")
    description = raw.get("description")
    if description is not None and not isinstance(description, str):
        raise KnowledgeError(f"{where}: description must be a string")
    for key in ("rationale", "evidence"):  # why the entry is right, and where that was shown
        text = raw.get(key)
        if not isinstance(text, str) or not text.strip():
            raise KnowledgeError(f"{where}: `{key}` must be a non-empty string")
    return {"type": kind, "value": value, "description": description,
            "rationale": raw["rationale"].strip(), "evidence": raw["evidence"].strip()}


def _build(entries: list[dict[str, Any]], origin: str, *, base: Knowledge | None = None,
           version: str = "", sha256: str = "") -> Knowledge:
    sets: dict[str, set[str]] = {
        "flask_request_attr": set(base.flask_request_attrs) if base else set(),
        "request_param_attr": set(base.request_param_attrs) if base else set(),
        "request_param_name": set(base.request_param_names) if base else set(),
        "route_decorator": set(base.route_decorators) if base else set(),
    }
    names = dict(base.source_names) if base else {}
    provenance = dict(base.provenance) if base else {}
    details = dict(base.details) if base else {}
    for e in entries:
        key = (e["type"], e["value"])
        if e["type"] == "source_name":
            if e["value"] in names:
                continue  # never replace an existing description (or its provenance)
            names[e["value"]] = e["description"] or f"untrusted input ({e['value']})"
        else:
            if e["value"] in sets[e["type"]]:
                continue
            sets[e["type"]].add(e["value"])
        provenance[key] = origin
        details[key] = {"rationale": e["rationale"], "evidence": e["evidence"]}
    return Knowledge(frozenset(sets["flask_request_attr"]), frozenset(sets["request_param_attr"]),
                     frozenset(sets["request_param_name"]), names, frozenset(sets["route_decorator"]),
                     version or (base.version if base else ""), sha256 or (base.sha256 if base else ""), provenance,
                     details)


def load_builtin() -> Knowledge:
    raw = resources.files("hackscan.taint").joinpath("knowledge.json").read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("entries"), list):
        raise KnowledgeError(f"built-in knowledge: expected schema {SCHEMA}")
    entries = [_entry(e, allowed=frozenset(TYPES), where=f"built-in {i + 1}") for i, e in enumerate(data["entries"])]
    return _build(entries, BUILT_IN, version=str(data.get("version", "")), sha256=hashlib.sha256(raw).hexdigest())


BUILTIN = load_builtin()
_active: contextvars.ContextVar[Knowledge] = contextvars.ContextVar("hackscan_knowledge", default=BUILTIN)


def active() -> Knowledge:
    return _active.get()


def use(knowledge: Knowledge) -> contextvars.Token:
    """Make `knowledge` active in the current context; returns the token that `restore` undoes."""
    return _active.set(knowledge)


def restore(token: contextvars.Token) -> None:
    _active.reset(token)


def for_config(entries: tuple[dict[str, Any], ...] | list[dict[str, Any]], enabled: bool) -> Knowledge:
    """The knowledge a scan uses: the built-ins, plus project entries when they are enabled."""
    return BUILTIN.with_entries(list(entries)) if enabled and entries else BUILTIN
