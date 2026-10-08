from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from hackscan.config import HackScanConfig
from hackscan.core.models import Fix, FixEdit, Region
from hackscan.core.pipeline import scan
from hackscan.plugins.loader import builtin_plugins
from hackscan.sarif.generator import FINGERPRINT_KEY, export_sarif

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMA = json.loads((FIXTURES / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
CORPUS = Path(__file__).parent / "corpus"


def validate(log: dict) -> None:
    jsonschema.Draft4Validator(SCHEMA).validate(json.loads(json.dumps(log)))


@pytest.fixture(scope="module")
def corpus_log():
    result = scan(CORPUS, HackScanConfig())
    return result, export_sarif(result, builtin_plugins())


def test_corpus_sarif_validates_against_official_schema(corpus_log):
    _, log = corpus_log
    validate(log)
    assert log["version"] == "2.1.0"


def test_rules_and_results_are_consistent(corpus_log):
    result, log = corpus_log
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({f.rule_id for f in result.findings})
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["partialFingerprints"][FINGERPRINT_KEY].startswith("hs1-")
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert not Path(loc["artifactLocation"]["uri"]).is_absolute()
    assert len(run["results"]) == len(result.findings)
    sqli = next(r for r in rules if r["id"] == "HS-SQLI-001")
    assert "external/cwe/cwe-89" in sqli["properties"]["tags"]
    assert sqli["properties"]["security-severity"] == "8.0"


def test_suppressed_findings_carry_suppressions(corpus_log):
    _, log = corpus_log
    results = log["runs"][0]["results"]
    suppressed = [r for r in results if r.get("suppressions")]
    assert suppressed
    kinds = {s["kind"] for r in suppressed for s in r["suppressions"]}
    assert kinds == {"external", "inSource"}  # taint verdicts and `# hackscan: ignore`
    assert all(r["properties"]["status"] == "suppressed" for r in suppressed)


def test_fixes_are_exported_and_valid(corpus_log):
    result, _ = corpus_log
    from dataclasses import replace

    f = result.findings[0]
    edit = FixEdit(Region(f.location.path, f.location.start_line, 1, f.location.start_line, 5), "x")
    fixed = replace(f, fix=Fix("Use parameters", (edit,), "template"))
    result.findings[0] = fixed
    log = export_sarif(result, builtin_plugins())
    validate(log)
    fixes = log["runs"][0]["results"][0]["fixes"]
    assert fixes[0]["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"] == "x"


def test_imported_rules_get_descriptors_and_validate():
    imports = FIXTURES / "imports"
    config = HackScanConfig(
        imports=(("codeql", imports / "codeql.sarif"), ("gitleaks", imports / "gitleaks.json"))
    )
    result = scan(imports / "project", config)
    log = export_sarif(result, builtin_plugins())
    validate(log)
    ids = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert "gitleaks:generic-api-key" in ids
    # Secrets never leak into the SARIF log.
    assert "hackscan-fake-token-0123456789" not in json.dumps(log)


def test_sarif_is_deterministic():
    a = export_sarif(scan(CORPUS, HackScanConfig()), builtin_plugins())
    b = export_sarif(scan(CORPUS, HackScanConfig(jobs=2)), builtin_plugins())
    assert a["runs"][0]["results"] == b["runs"][0]["results"]
