"""Configuration: `.hackscan.yml` discovery, validation and CLI overrides.

Discovery is hierarchical: every `.hackscan.yml` from the filesystem root down to the
scan root is loaded and merged, nearer files overriding farther ones (lists such as
`ignore` are concatenated). CLI options override the merged file configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from hackscan.core.models import Severity

CONFIG_NAME = ".hackscan.yml"
# Keys accepted in .hackscan.yml (and only these: anything else is an error, so a typo
# never silently disables a setting).
CONFIG_KEYS = frozenset(
    {
        "ignore",
        "severity",
        "min-confidence",
        "fail-on",
        "show-suppressed",
        "plugins",
        "taint",
        "with",
        "import",
        "tool-timeout",
        "strict-tools",
        "allow-incomplete",
        "jobs",
    }
)

DEFAULT_IGNORES = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    ".tox",
    ".nox",
    "node_modules",
    "build",
    "dist",
    "site-packages",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".eggs",
    "*.egg-info",
)

KNOWN_TOOLS = ("semgrep", "bandit", "gitleaks")
IMPORT_FORMATS = ("sarif", "semgrep", "bandit", "codeql", "gitleaks")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class HackScanConfig:
    ignore: tuple[str, ...] = ()
    severity: Severity = Severity.LOW  # minimum severity reported
    min_confidence: int = 0
    fail_on: Severity | None = None
    show_suppressed: bool = False
    plugins: Path | None = None
    taint: bool = True
    with_tools: tuple[str, ...] = ()
    imports: tuple[tuple[str, Path], ...] = ()  # (format, report file)
    tool_timeout: int = 300
    strict_tools: bool = False
    allow_incomplete: bool = False  # files that cannot be analyzed do not fail the run
    jobs: int = 0  # 0 = automatic
    sources: tuple[Path, ...] = field(default=(), compare=False)  # config files loaded

    def with_overrides(self, **overrides: Any) -> HackScanConfig:
        """Apply CLI overrides; `None` means "not given". `ignore` is appended."""
        values = {k: v for k, v in overrides.items() if v is not None}
        if "ignore" in values:
            values["ignore"] = (*self.ignore, *values["ignore"])
        return replace(self, **values)


def discover(scan_root: Path) -> list[Path]:
    """Config files from the filesystem root down to `scan_root` (nearest last)."""
    start = scan_root if scan_root.is_dir() else scan_root.parent
    found = [d / CONFIG_NAME for d in [start.resolve(), *start.resolve().parents]]
    return [p for p in reversed(found) if p.is_file()]


def load(scan_root: Path, explicit: Path | None = None) -> HackScanConfig:
    paths = [explicit] if explicit is not None else discover(scan_root)
    config = HackScanConfig()
    for path in paths:
        config = _merge(config, _parse(path), path)
    return config


def _parse(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot read config: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    unknown = sorted(set(data) - CONFIG_KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown option(s): {', '.join(unknown)}")
    return data


def _merge(config: HackScanConfig, data: dict[str, Any], path: Path) -> HackScanConfig:
    def err(message: str) -> ConfigError:
        return ConfigError(f"{path}: {message}")

    values: dict[str, Any] = {}
    if "ignore" in data:
        ignore = data["ignore"]
        if not isinstance(ignore, list) or not all(isinstance(i, str) for i in ignore):
            raise err("`ignore` must be a list of glob strings")
        values["ignore"] = (*config.ignore, *ignore)
    for key in ("severity", "fail-on"):
        if key in data:
            try:
                values[key.replace("-", "_")] = Severity(str(data[key]).lower())
            except ValueError:
                options = ", ".join(s.value for s in Severity)
                raise err(f"`{key}` must be one of: {options}") from None
    if "min-confidence" in data:
        value = data["min-confidence"]
        if not isinstance(value, int) or not 0 <= value <= 100:
            raise err("`min-confidence` must be an integer 0-100")
        values["min_confidence"] = value
    for key in ("show-suppressed", "taint", "strict-tools", "allow-incomplete"):
        if key in data:
            if not isinstance(data[key], bool):
                raise err(f"`{key}` must be true or false")
            values[key.replace("-", "_")] = data[key]
    for key in ("tool-timeout", "jobs"):
        if key in data:
            if not isinstance(data[key], int) or data[key] < 0:
                raise err(f"`{key}` must be a non-negative integer")
            values[key.replace("-", "_")] = data[key]
    if "plugins" in data:
        values["plugins"] = (path.parent / str(data["plugins"])).resolve()
    if "with" in data:
        values["with_tools"] = parse_tools(data["with"], err)
    if "import" in data:
        items = data["import"]
        if not isinstance(items, dict):
            raise err("`import` must map format to report path, e.g. {codeql: results.sarif}")
        values["imports"] = tuple(
            (parse_import_format(fmt, err), (path.parent / str(p)).resolve())
            for fmt, p in items.items()
        )
    return replace(config, sources=(*config.sources, path), **values)


def parse_tools(value: Any, err=ConfigError) -> tuple[str, ...]:
    items = value.split(",") if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)):
        raise err("`with` must be a list or comma-separated string of tools")
    tools = tuple(dict.fromkeys(str(t).strip().lower() for t in items if str(t).strip()))
    unknown = [t for t in tools if t not in KNOWN_TOOLS]
    if unknown:
        raise err(f"unknown tool(s) {', '.join(unknown)}; supported: {', '.join(KNOWN_TOOLS)}")
    return tools


def parse_import_format(value: Any, err=ConfigError) -> str:
    fmt = str(value).strip().lower()
    if fmt not in IMPORT_FORMATS:
        raise err(f"unknown import format {fmt!r}; supported: {', '.join(IMPORT_FORMATS)}")
    return fmt
