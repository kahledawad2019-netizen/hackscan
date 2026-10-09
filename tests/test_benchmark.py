from __future__ import annotations

import importlib.util
import json
import sys
import textwrap
from pathlib import Path

import pytest

BENCH = Path(__file__).parent.parent / "benchmarks"


def _load():
    spec = importlib.util.spec_from_file_location("bench_run", BENCH / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_run"] = module
    spec.loader.exec_module(module)
    return module


bench = _load()


def write_suite(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, code in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(textwrap.dedent(code), encoding="utf-8")
    return tmp_path


SAMPLE = """
import os

def a(x):
    os.system(x)  # vuln: cmdi

def b():
    os.system("ls")  # safe: cmdi

class C:
    def m(self, q):
        cur.execute(  # vuln: sqli
            q
        )
"""


def test_labels_are_per_function(tmp_path):
    labels = bench.load_labels(write_suite(tmp_path, {"m.py": SAMPLE}))
    assert [(lb.function, lb.cls, lb.vulnerable) for lb in labels] == [
        ("a", "cmdi", True),
        ("b", "cmdi", False),
        ("C.m", "sqli", True),
    ]


@pytest.mark.parametrize(
    "code",
    [
        "import os\nos.system(x)  # vuln: cmdi\n",  # module level
        "def f():\n    a(x)  # vuln: cmdi\n    b(x)  # safe: cmdi\n",  # two in one function
        "def f():\n    a(\n        x  # vuln: cmdi\n    )\n",  # not a statement's first line
        "def f():\n    a(x)  # vuln: xss\n",  # unknown class
    ],
)
def test_bad_labels_are_rejected(tmp_path, code):
    suite = write_suite(tmp_path, {"m.py": code})
    with pytest.raises(ValueError):
        bench.load_labels(suite)


def test_scoring_is_per_function_and_class(tmp_path):
    code = """
    import os

    def a(x):
        cmd = "ls " + x
        os.system(cmd)  # vuln: cmdi

    def b():
        os.system("ls")  # safe: cmdi

    def c(x):
        eval(x)  # vuln: codei

    def d():
        pass
    """
    suite = write_suite(tmp_path, {"m.py": code})
    labels = bench.load_labels(suite)
    R = bench.Report
    reports = [
        R("m.py", 5, "cmdi"),  # flow start inside `a`: counts for a's sink
        R("m.py", 6, "cmdi"),  # duplicate in the same function: no extra credit or FP
        R("m.py", 9, "cmdi"),  # trap
        R("m.py", 12, "cmdi"),  # wrong class for `c`
        R("m.py", 15, "sqli"),  # unlabeled function
        R("m.py", 2, "cmdi"),  # module level (an import warning)
        R("m.py", 9, "other:CWE-1"),  # other classes are ignored
    ]
    scores = bench.score(labels, reports, suite)
    assert (scores["cmdi"].tp, scores["cmdi"].fp, scores["cmdi"].fn) == (1, 3, 0)
    assert scores["cmdi"].trap_hits == 1
    assert (scores["codei"].tp, scores["codei"].fn) == (0, 1)
    assert (scores["sqli"].fp, scores["all"].tp, scores["all"].fp, scores["all"].fn) == (
        1,
        1,
        4,
        1,
    )
    assert scores["all"].precision == pytest.approx(1 / 5)
    assert scores["all"].recall == pytest.approx(1 / 2)
    assert bench.Score().precision is None and bench.Score().f1 is None


def test_suite_labels_are_well_formed():
    labels = bench.load_labels()
    assert {lb.cls for lb in labels} == set(bench.CLASSES)
    assert sum(lb.vulnerable for lb in labels) >= 20
    assert sum(not lb.vulnerable for lb in labels) >= 20


def test_published_hackscan_numbers_are_current():
    """RESULTS.json is what README quotes; it must match the engine as committed."""
    published = json.loads((BENCH / "RESULTS.json").read_text(encoding="utf-8"))["tools"]
    labels = bench.load_labels()
    for confirmed_only in (False, True):
        result = bench.run_hackscan(bench.SUITE, confirmed_only=confirmed_only)
        current = {
            cls: {"tp": s.tp, "fp": s.fp, "fn": s.fn, "trap_hits": s.trap_hits}
            for cls, s in bench.score(labels, result.reports).items()
        }
        assert published[result.name]["scores"] == current, result.name


def test_reports_count_for_the_innermost_function(tmp_path):
    code = """
    import os

    def outer(x):
        def inner():
            os.system(x)  # vuln: cmdi

        os.system("ls")  # safe: cmdi
        return inner
    """
    suite = write_suite(tmp_path, {"m.py": code})
    labels = bench.load_labels(suite)
    assert [lb.function for lb in labels] == ["outer.inner", "outer"]
    scores = bench.score(labels, [bench.Report("m.py", 6, "cmdi")], suite)
    assert (scores["cmdi"].tp, scores["cmdi"].fp) == (1, 0)


def test_app_review_is_well_formed():
    review = json.loads((BENCH / "apps_review.json").read_text(encoding="utf-8"))
    for app, verdicts in review.items():
        for key, entry in verdicts.items():
            path, function, cls = key.split("::")
            assert path.endswith(".py") and function and cls in bench.CLASSES, (app, key)
            assert entry["verdict"] in {"tp", "fp"} and entry["note"], (app, key)
            assert "vuln" not in entry or entry["verdict"] == "tp", (app, key)


def _load_apps():
    spec = importlib.util.spec_from_file_location("bench_apps", BENCH / "apps.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_apps"] = module
    spec.loader.exec_module(module)
    return module


apps = _load_apps()
README = (BENCH.parent / "README.md").read_text(encoding="utf-8")


def test_results_markdown_and_readme_match_the_json():
    data = json.loads((BENCH / "RESULTS.json").read_text(encoding="utf-8"))
    assert (BENCH / "RESULTS.md").read_text(encoding="utf-8") == bench.render(data)
    rows = bench.overall_rows(data)
    assert len(rows) == len(data["tools"]) >= 5
    for row in rows:
        assert row in README, row


def test_apps_markdown_and_readme_match_the_json():
    summary = json.loads((BENCH / "APPS.json").read_text(encoding="utf-8"))
    assert (BENCH / "APPS.md").read_text(encoding="utf-8") == apps.render(summary)
    rows = apps.total_rows(summary)
    assert len(rows) >= 5
    for row in rows:
        assert row.replace("| **all** ", "", 1) in README, row
    assert f"{apps.totals(summary)['all_vulns']} distinct" in README


def test_f1_is_zero_when_nothing_is_found():
    assert bench.Score(tp=0, fp=1, fn=1).f1 == 0
    assert bench.Score().f1 is None
    assert bench.Score(tp=2, fp=1, fn=1).f1 == pytest.approx(2 / 3)


@pytest.mark.parametrize(
    "name",
    [
        "repo/../escape.py",
        "repo/..\\..\\escape.py",
        "repo/\\escape.py",
        "repo/C:/escape.py",
        "/abs/escape.py",
        "repo",
    ],
)
def test_unsafe_archive_names_are_rejected(name):
    assert apps.safe_member_path(name) is None


def test_safe_archive_names_are_kept():
    assert apps.safe_member_path("repo-abc/app/views.py") == ("app", "views.py")


def _tarball(entries) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                info.type = tarfile.SYMTYPE
                info.linkname = data
                archive.addfile(info)
    return buffer.getvalue()


def test_extraction_keeps_only_safe_python_files(tmp_path):
    data = _tarball(
        [
            ("repo/app/views.py", b"x = 1\n", "file"),
            ("repo/README.md", b"docs", "file"),
            ("repo/../escape.py", b"bad", "file"),
            ("repo/..\\escape2.py", b"bad", "file"),
            ("repo/link.py", "/etc/passwd", "link"),
        ]
    )
    target = tmp_path / "out" / "app"
    apps.extract_python(data, target)
    found = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    assert found == ["app/views.py"]
    assert not list(tmp_path.rglob("escape*"))


def test_extraction_limits_expanded_size(tmp_path, monkeypatch):
    monkeypatch.setattr(apps, "MAX_FILE", 10)
    data = _tarball([("repo/big.py", b"x" * 11, "file")])
    with pytest.raises(RuntimeError, match="larger than"):
        apps.extract_python(data, tmp_path / "app")
    monkeypatch.setattr(apps, "MAX_FILE", 100)
    monkeypatch.setattr(apps, "MAX_TOTAL", 15)
    data = _tarball([("repo/a.py", b"x" * 10, "file"), ("repo/b.py", b"x" * 10, "file")])
    with pytest.raises(RuntimeError, match="expands beyond"):
        apps.extract_python(data, tmp_path / "app2")
    assert not (tmp_path / "app2").exists()


SARIF_RESULT = {
    "ruleId": "B602",
    "message": {"text": "shell"},
    "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "m.py"}, "region": {"startLine": 2}}}
    ],
}


def _sarif(tmp_path, data, text=None):
    file = tmp_path / "r.sarif"
    file.write_text(text if text is not None else json.dumps(data), encoding="utf-8")
    (tmp_path / "m.py").write_text("import os\nos.system(x)\n", encoding="utf-8")
    return bench.sarif_reports(file, tmp_path, "bandit")


def test_complete_sarif_is_scored(tmp_path):
    log = {"runs": [{"tool": {"driver": {"name": "Bandit"}}, "results": [SARIF_RESULT]}]}
    reports, problem = _sarif(tmp_path, log)
    assert problem is None
    assert [(r.path, r.line, r.cls) for r in reports] == [("m.py", 2, "cmdi")]


@pytest.mark.parametrize(
    ("data", "text", "message"),
    [
        ({}, None, "no runs"),
        ({"runs": []}, None, "no runs"),
        ({"runs": [{"tool": {}}]}, None, "no result list"),
        (None, "{not json", "unreadable"),
        (
            {"runs": [{"tool": {"driver": {"name": "Bandit"}}, "results": [{"ruleId": "B602"}]}]},
            None,
            "not imported",
        ),
    ],
)
def test_incomplete_sarif_is_skipped_not_scored(tmp_path, data, text, message):
    reports, problem = _sarif(tmp_path, data, text)
    assert reports == []
    assert message in problem


def test_unavailable_codeql_is_skipped(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEQL", str(tmp_path / "missing-codeql.exe"))
    result = bench.run_codeql(tmp_path)
    assert result.skipped
    assert result.reports == []


def test_changed_semgrep_ruleset_is_skipped(monkeypatch, tmp_path):
    monkeypatch.setattr(bench, "CACHE", tmp_path)
    (tmp_path / "semgrep-p-python.yml").write_text("rules: []\n", encoding="utf-8")
    rules, detail = bench.semgrep_rules()
    assert rules is None
    assert "ruleset changed" in detail


def test_unreviewed_rows_publish_no_metrics():
    verdicts = {"a.py::f::sqli": {"verdict": "tp", "note": "x"}}
    found = {"Tool": {("a.py", "f", "sqli"), ("a.py", "g", "sqli")}}
    entry = apps.score_app(verdicts, found)
    assert entry["tools"]["Tool"]["unreviewed"] == 1
    summary = {"apps": {"x": {"repo": "o/r", "commit": "c", **entry}}}
    text = apps.render(summary)
    assert "incomplete: 1 unreviewed" in text
    assert "100%" not in text


def test_published_app_review_is_complete():
    summary = json.loads((BENCH / "APPS.json").read_text(encoding="utf-8"))
    for app in summary["apps"].values():
        assert "skipped" not in app
        assert all(t["unreviewed"] == 0 for t in app["tools"].values())


def test_dot_components_are_rejected_before_normalization():
    assert apps.safe_member_path("repo/./x.py") is None
    assert apps.safe_member_path("repo//x.py") is None


def test_malformed_run_metadata_is_not_a_crash(tmp_path):
    reports, problem = _sarif(tmp_path, {"runs": [{"tool": None, "results": []}]})
    assert reports == [] and problem is None


def test_relative_recall_needs_a_complete_review():
    verdicts = {"a.py::f::sqli": {"verdict": "tp", "note": "x"}}
    found = {"A": {("a.py", "f", "sqli")}, "B": {("a.py", "g", "sqli")}}
    entry = apps.score_app(verdicts, found)
    assert entry["complete"] is False
    summary = {"apps": {"x": {"repo": "o/r", "commit": "c", **entry}}}
    rows = apps.render(summary).splitlines()
    row_a = next(r for r in rows if r.startswith("| x | A |"))
    assert row_a.endswith("| 100% | - |")  # precision known, recall not
    total_a = next(r for r in apps.total_rows(summary) if "| A |" in r)
    assert total_a.endswith("| - |")
