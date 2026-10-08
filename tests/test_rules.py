"""Corpus-driven rule tests: every `# expect:` annotation must match exactly.

Reports precision/recall-style diffs (missing = false negatives, unexpected = false positives).
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from vulnhawk.analyzers.ast_pass import analyze_file
from vulnhawk.core.models import Status
from vulnhawk.plugins.loader import builtin_plugins

CORPUS = Path(__file__).parent / "corpus"
EXPECT_RE = re.compile(r"#\s*expect:\s*(?P<rules>[A-Za-z0-9:_\-. ]+)")
CORPUS_FILES = sorted(p for p in CORPUS.rglob("*.py"))


def expected_findings(path: Path) -> Counter[tuple[int, str]]:
    expected: Counter[tuple[int, str]] = Counter()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = EXPECT_RE.search(line)
        if match:
            for rule in match.group("rules").split():
                expected[(lineno, rule)] += 1
    return expected


@pytest.mark.parametrize("path", CORPUS_FILES, ids=lambda p: p.relative_to(CORPUS).as_posix())
def test_corpus_file(path: Path):
    result = analyze_file(path, CORPUS, builtin_plugins())
    assert not result.errors
    actual = Counter(
        (f.location.start_line, f.rule_id)
        for f in result.findings
        if f.status is not Status.SUPPRESSED
    )
    expected = expected_findings(path)
    missing = expected - actual
    unexpected = actual - expected
    assert not missing and not unexpected, (
        f"\nfalse negatives (missing): {sorted(missing.elements())}"
        f"\nfalse positives (unexpected): {sorted(unexpected.elements())}"
    )
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
