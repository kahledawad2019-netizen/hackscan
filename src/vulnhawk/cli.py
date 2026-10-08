"""Command-line entry point. The `scan` command lands in M3."""

from __future__ import annotations

import click

from vulnhawk import __version__


@click.group()
@click.version_option(__version__, prog_name="vulnhawk")
def main() -> None:
    """VulnHawk: Python SAST orchestrator and verifier."""
