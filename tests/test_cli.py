from __future__ import annotations

from click.testing import CliRunner

from vulnhawk import __version__
from vulnhawk.cli import main


def test_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
