"""Rule plugin API: built-in rules and user plugins share the same interface."""

from hackscan.plugins.base import FileContext, Match, RulePlugin

__all__ = ["FileContext", "Match", "RulePlugin"]
