"""Built-in rule registry and user plugin discovery.

User plugins are `.py` files in a directory passed via `--plugins`; every concrete
`RulePlugin` subclass they define is instantiated. Loading a plugin executes its code, so
it is strictly opt-in.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import sys
from pathlib import Path

from vulnhawk.core.models import Severity
from vulnhawk.plugins.base import RulePlugin
from vulnhawk.plugins.rules.cmdi import CommandInjection
from vulnhawk.plugins.rules.codei import CodeInjection
from vulnhawk.plugins.rules.sqli import SqlInjection
from vulnhawk.plugins.rules.weak_crypto import WeakHash

BUILTIN_RULES: tuple[type[RulePlugin], ...] = (
    SqlInjection,
    CommandInjection,
    CodeInjection,
    WeakHash,
)


class PluginError(Exception):
    pass


def builtin_plugins() -> list[RulePlugin]:
    return [cls() for cls in BUILTIN_RULES]


def load_plugins(directory: Path) -> list[RulePlugin]:
    """Instantiate every concrete RulePlugin defined in `directory/*.py` (sorted by file)."""
    if not directory.is_dir():
        raise PluginError(f"plugin directory not found: {directory}")
    plugins: list[RulePlugin] = []
    for path in sorted(directory.glob("*.py")):
        module_name = f"vulnhawk_user_plugin_{path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise PluginError(f"cannot load plugin file: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # surface any import-time failure with the file name
            raise PluginError(f"error loading plugin {path.name}: {exc}") from exc
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, RulePlugin)
                and obj is not RulePlugin
                and obj.__module__ == module_name
                and not inspect.isabstract(obj)
            ):
                plugins.append(_validated(obj(), path))
    return plugins


def _validated(plugin: RulePlugin, path: Path) -> RulePlugin:
    cls = type(plugin).__name__
    for attr in ("rule_id", "name", "description"):
        value = getattr(plugin, attr, None)
        if not isinstance(value, str) or not value.strip():
            raise PluginError(f"{path.name}: {cls}.{attr} must be a non-empty string")
    if not isinstance(getattr(plugin, "severity", None), Severity):
        raise PluginError(f"{path.name}: {cls}.severity must be a vulnhawk Severity")
    node_types = getattr(plugin, "node_types", None)
    if (
        not isinstance(node_types, tuple)
        or not node_types
        or not all(isinstance(t, type) and issubclass(t, ast.AST) for t in node_types)
    ):
        raise PluginError(f"{path.name}: {cls}.node_types must be a tuple of ast node classes")
    if not isinstance(plugin.cwe, tuple) or not all(isinstance(c, str) for c in plugin.cwe):
        raise PluginError(f"{path.name}: {cls}.cwe must be a tuple of strings")
    if not isinstance(plugin.default_confidence, int) or not 0 <= plugin.default_confidence <= 100:
        raise PluginError(f"{path.name}: {cls}.default_confidence must be an int 0-100")
    if plugin.rule_id.startswith("VH-"):
        raise PluginError(f"{path.name}: rule id prefix `VH-` is reserved for built-in rules")
    return plugin


def resolve_plugins(extra_dir: Path | None = None) -> list[RulePlugin]:
    plugins = builtin_plugins()
    if extra_dir is not None:
        plugins.extend(load_plugins(extra_dir))
    ids = [p.rule_id for p in plugins]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise PluginError(f"duplicate rule ids: {', '.join(duplicates)}")
    return plugins
