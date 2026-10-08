from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from rich.console import Console

from hackscan.cli import main
from hackscan.config import HackScanConfig
from hackscan.core.models import Severity
from hackscan.core.pipeline import scan
from hackscan.ui.render import banner, render

FRAMEWORKS = Path(__file__).parent / "corpus" / "frameworks"


def recorded(fn) -> str:
    console = Console(record=True, width=120, force_terminal=True, color_system="truecolor")
    fn(console)
    return console.export_text()


def test_render_shows_findings_summary_and_traces():
    result = scan(FRAMEWORKS, HackScanConfig())
    config = HackScanConfig(fail_on=Severity.HIGH)
    out = recorded(lambda c: render(c, result, result.findings, config))
    assert "HS-SQLI-001" in out and "confirmed" in out
    assert "Untrusted" in out  # taint trace
    assert "Summary" in out and "fail-on high" in out
    assert "suppressed" in out  # suppressed shown when passed in


def test_banner_mentions_version():
    from hackscan import __version__

    assert __version__ in recorded(banner)


def test_render_no_findings():
    result = scan(FRAMEWORKS, HackScanConfig())
    assert "No findings." in recorded(lambda c: render(c, result, [], HackScanConfig()))


def test_color_always_uses_rich_and_never_uses_plain():
    rich_out = CliRunner().invoke(main, ["scan", str(FRAMEWORKS), "--color", "always"]).output
    assert "\x1b[" in rich_out and "Summary" in rich_out
    plain = CliRunner().invoke(main, ["scan", str(FRAMEWORKS), "--color", "never"]).output
    assert "\x1b[" not in plain and plain.startswith("HackScan ")


def test_auto_is_plain_when_not_a_terminal():
    out = CliRunner().invoke(main, ["scan", str(FRAMEWORKS)]).output
    assert "\x1b[" not in out


def test_machine_formats_never_use_rich():
    for fmt in ("json", "sarif"):
        out = (
            CliRunner()
            .invoke(main, ["scan", str(FRAMEWORKS), "--format", fmt, "--color", "always"])
            .output
        )
        assert out.lstrip().startswith("{")


def test_rich_exit_codes_match_plain():
    args = ["scan", str(FRAMEWORKS), "--fail-on", "high"]
    assert CliRunner().invoke(main, [*args, "--color", "always"]).exit_code == 1
    assert CliRunner().invoke(main, [*args, "--color", "never"]).exit_code == 1


def test_control_sequences_from_model_or_code_are_neutralized(tmp_path):
    from dataclasses import replace

    from hackscan.core.models import Evidence

    result = scan(FRAMEWORKS, HackScanConfig())
    evil = "reviewed\x1b[2J\x1b[Hspoofed"
    f = replace(
        result.findings[0],
        message="msg\x1b]0;title\x07",
        evidence=(Evidence("llm", "llm_rationale", evil),),
    )
    out = recorded(lambda c: render(c, result, [f], HackScanConfig()))
    assert "\x1b[2J" not in out and "\x1b]0;" not in out
    assert "\\x1b[2J" in out  # shown escaped, visibly

    from hackscan.cli import _text

    plain = _text(result, [f], HackScanConfig(), quiet=False)
    from hackscan.core.redact import strip_controls

    assert "\x1b" not in strip_controls(plain)


def test_fix_diff_context_is_redacted(tmp_path):
    secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    (tmp_path / "m.py").write_text(
        f'import hashlib\napi_key = "{secret}"\n\ndef f(d):\n    return hashlib.md5(d).hexdigest()\n'
    )
    out = (
        CliRunner().invoke(main, ["scan", str(tmp_path), "--show-fixes", "--color", "never"]).output
    )
    assert "hashlib.sha256" in out
    assert secret not in out


def test_fix_diff_redacts_split_secrets(tmp_path):
    (tmp_path / "m.py").write_text(
        'import hashlib\n\ndef f(d):\n    api_key = (\n        "alpha12345"\n        "beta67890"\n    )\n'
        "    return hashlib.md5(d).hexdigest()\n"
    )
    out = (
        CliRunner().invoke(main, ["scan", str(tmp_path), "--show-fixes", "--color", "never"]).output
    )
    assert "hashlib.sha256" in out
    assert "alpha12345" not in out and "beta67890" not in out
