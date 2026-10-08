"""Command-line entry point. The `scan` command lands in M3."""

from __future__ import annotations

import click

from hackscan import __version__


@click.group()
@click.version_option(__version__, prog_name="hackscan")
def main() -> None:
    """HackScan: Python SAST orchestrator and verifier."""
