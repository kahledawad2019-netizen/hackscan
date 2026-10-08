"""Corpus-driven rule tests: every `# expect:` annotation must match exactly.

Reports precision/recall-style diffs (missing = false negatives, unexpected = false positives).
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from hackscan.analyzers.ast_pass import analyze_file
from hackscan.core.models import Status
from hackscan.plugins.loader import builtin_plugins

CORPUS = Path(__file__).parent / "corpus"
EXPECT_RE = re.compile(r"#\s*expect:\s*(?P<rules>[A-Za-z0-9:_\-.! ]+)")
SUPPRESSED_RE = re.compile(r"#\s*expect-suppressed:\s*(?P<rule>\S+)\s+(?P<reason>\S+)")
# Flipped to True when the taint pass (M2) runs in this harness: expect-suppressed
# findings must then be suppressed with the stated reason, not merely present.
TAINT_PASS_ENABLED = True
CORPUS_FILES = sorted(p for p in CORPUS.rglob("*.py"))


def expected_suppressed(path: Path) -> dict[tuple[int, str], str]:
    out: dict[tuple[int, str], str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = SUPPRESSED_RE.search(line)
        if match:
            out[(lineno, match.group("rule"))] = match.group("reason")
    return out


def _expect_tokens(path: Path) -> list[tuple[int, str]]:
    tokens = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = EXPECT_RE.search(line)
        if match:
            tokens += [(lineno, rule) for rule in match.group("rules").split()]
    return tokens


def expected_findings(path: Path) -> Counter[tuple[int, str]]:
    """Open findings per (line, rule). A trailing `!` additionally requires `confirmed`."""
    return Counter((line, rule.rstrip("!")) for line, rule in _expect_tokens(path))


def expected_confirmed(path: Path) -> Counter[tuple[int, str]]:
    return Counter((line, rule[:-1]) for line, rule in _expect_tokens(path) if rule.endswith("!"))


@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.relative_to(CORPUS).as_posix())
def test_corpus_file(path: Path):
    result = analyze_file(path, CORPUS, builtin_plugins())
    assert not result.errors
    suppressed = expected_suppressed(path)
    for key, reason in suppressed.items():
        hits = [f for f in result.findings if (f.location.start_line, f.rule_id) == key]
        assert hits, f"expected (suppressed) finding missing: {key}"
        if TAINT_PASS_ENABLED:
            assert all(f.status is Status.SUPPRESSED for f in hits), key
            assert all(f.suppression == reason for f in hits), key
    actual = Counter(
        (f.location.start_line, f.rule_id)
        for f in result.findings
        if f.status is not Status.SUPPRESSED
        and (f.location.start_line, f.rule_id) not in suppressed
    )
    expected = expected_findings(path)
    missing = expected - actual
    unexpected = actual - expected
    assert not missing and not unexpected, (
        f"\nfalse negatives (missing): {sorted(missing.elements())}"
        f"\nfalse positives (unexpected): {sorted(unexpected.elements())}"
    )
    confirmed = Counter(
        (f.location.start_line, f.rule_id) for f in result.findings if f.status is Status.CONFIRMED
    )
    not_confirmed = expected_confirmed(path) - confirmed
    assert not not_confirmed, f"expected taint-confirmed: {sorted(not_confirmed.elements())}"
    if "safe" in path.parts:
        assert not expected, "safe corpus files must not carry expectations"


def test_every_builtin_rule_has_vulnerable_and_safe_corpus():
    rules = {p.rule_id for p in builtin_plugins()}
    covered = Counter()
    for path in CORPUS_FILES:
        for (_, rule), n in expected_findings(path).items():
            covered[rule] += n
    assert rules <= set(covered), f"rules without vulnerable cases: {rules - set(covered)}"
    for rule_dir in ("sqli", "cmdi", "codei", "weak_crypto"):
        assert list((CORPUS / rule_dir / "safe").glob("*.py")), f"{rule_dir} has no safe cases"
