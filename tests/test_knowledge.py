"""Security knowledge as data (hackscan.taint.knowledge): provenance, project notes, parity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hackscan.cli import _json
from hackscan.config import ConfigError, HackScanConfig, load
from hackscan.core.models import Status
from hackscan.core.pipeline import scan
from hackscan.sarif.generator import export_sarif
from hackscan.taint import knowledge, sources
from hackscan.taint.knowledge import BUILT_IN, PROJECT_NOTE, KnowledgeError

CUSTOM = (
    "import subprocess\nfrom myframework import incoming\n\n"
    "subprocess.run(incoming.text, shell=True)\n"
)
NOTE = (
    "knowledge:\n  - type: source_name\n    value: myframework.incoming.text\n"
    "    description: body of an incoming message\n"
    "    rationale: messages come from remote clients\n    evidence: app/handlers.py receive()\n"
)
WHY = {"rationale": "comes from remote clients", "evidence": "synthetic test"}


def test_builtin_entries_are_marked_built_in():
    k = knowledge.BUILTIN
    assert k.provenance and set(k.provenance.values()) == {BUILT_IN}
    assert k.version and len(k.sha256) == 64
    assert "args" in k.flask_request_attrs and "sys.argv" in k.source_names


def test_compatibility_names_match_the_data():
    assert knowledge.BUILTIN.flask_request_attrs == sources.FLASK_REQUEST_ATTRS
    assert knowledge.BUILTIN.source_names == sources.SOURCE_NAMES
    assert knowledge.BUILTIN.route_decorators == sources.ROUTE_DECORATORS


def test_project_notes_only_add_and_are_marked_as_such():
    k = knowledge.BUILTIN.with_entries(
        [
            {"type": "source_name", "value": "x.y", "description": "mine", **WHY},
            {
                "type": "source_name",
                "value": "sys.argv",
                "description": "renamed",
                **WHY,
            },  # existing: kept as is
            {"type": "route_decorator", "value": "endpoint", **WHY},
        ]
    )
    assert k.details[("source_name", "x.y")] == WHY
    assert k.provenance[("source_name", "x.y")] == PROJECT_NOTE
    assert k.provenance[("route_decorator", "endpoint")] == PROJECT_NOTE
    assert k.source_names["sys.argv"] == knowledge.BUILTIN.source_names["sys.argv"]
    assert k.provenance[("source_name", "sys.argv")] == BUILT_IN
    assert knowledge.BUILTIN.source_names.keys() <= k.source_names.keys()


@pytest.mark.parametrize(
    "entry",
    [
        {"type": "sanitizer", "value": "escape", **WHY},
        {"type": "suppress", "value": "x", **WHY},
        {"type": "source_name", "value": "", **WHY},
        {"type": "source_name", "value": " x", **WHY},
        {"type": "source_name", "value": "x", "provenance": "built-in", **WHY},
        {"type": ["source_name"], "value": "x", **WHY},
        {"type": "source_name", "value": "x", "rationale": "r"},
        {"type": "source_name", "value": "x", "rationale": None, "evidence": []},
        {"type": "source_name", "value": "x", "rationale": " ", "evidence": "e"},
        "not a mapping",
    ],
)
def test_invalid_project_entries_are_refused(entry):
    with pytest.raises(KnowledgeError):
        knowledge.BUILTIN.with_entries([entry])


def test_project_entries_cannot_claim_built_in():
    with pytest.raises(KnowledgeError):
        knowledge.BUILTIN.with_entries(
            [{"type": "source_name", "value": "a.b", **WHY}], origin=BUILT_IN
        )


def test_config_parses_and_validates_knowledge(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text(NOTE)
    assert load(tmp_path).knowledge
    (tmp_path / ".hackscan.yml").write_text("knowledge:\n  - type: sanitizer\n    value: esc\n")
    with pytest.raises(ConfigError):
        load(tmp_path)
    (tmp_path / ".hackscan.yml").write_text("knowledge: nope\n")
    with pytest.raises(ConfigError):
        load(tmp_path)
    (tmp_path / ".hackscan.yml").write_text("knowledge:\n  - type: []\n    value: x\n")
    with pytest.raises(ConfigError):
        load(tmp_path)
    (tmp_path / ".hackscan.yml").write_text("knowledge:\n  - type: source_name\n    value: x.y\n")
    with pytest.raises(ConfigError):  # no rationale or evidence
        load(tmp_path)


ROUTE = (
    "import subprocess\nfrom flask import Flask\napp = Flask(__name__)\n\n"
    "@app.route('/run/<cmd>')\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
)


def test_a_note_never_removes_a_route_parameter_source(tmp_path: Path):
    (tmp_path / "app.py").write_text(ROUTE)
    before = _statuses(tmp_path, HackScanConfig())
    (tmp_path / ".hackscan.yml").write_text(
        "knowledge:\n  - type: request_param_name\n    value: cmd\n"
        "    rationale: r\n    evidence: e\n"
    )
    assert before == {Status.CONFIRMED}
    assert _statuses(tmp_path, load(tmp_path)) == before


def test_knowledge_is_isolated_between_threads():
    import threading

    noted = knowledge.BUILTIN.with_entries([{"type": "source_name", "value": "x.y", **WHY}])
    entered, checked = threading.Event(), threading.Event()
    seen = {}

    def first():
        token = knowledge.use(noted)
        entered.set()
        checked.wait(5)
        seen["first"] = knowledge.active() is noted
        knowledge.restore(token)

    def second():
        entered.wait(5)
        seen["second"] = knowledge.active() is knowledge.BUILTIN
        checked.set()

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(10)
    assert seen == {"first": True, "second": True}
    assert knowledge.active() is knowledge.BUILTIN


def _statuses(root: Path, config: HackScanConfig) -> set[Status]:
    return {f.status for f in scan(root, config).findings if f.rule_id.startswith("HS-CMDI")}


def test_a_project_note_adds_a_source_and_can_be_switched_off(tmp_path: Path):
    (tmp_path / "app.py").write_text(CUSTOM)
    assert _statuses(tmp_path, HackScanConfig()) == {Status.CANDIDATE}
    (tmp_path / ".hackscan.yml").write_text(NOTE)
    config = load(tmp_path)
    assert _statuses(tmp_path, config) == {Status.CONFIRMED}
    assert _statuses(tmp_path, config.with_overrides(project_knowledge=False)) == {Status.CANDIDATE}
    assert knowledge.active() is knowledge.BUILTIN  # restored after the scan


def test_parallel_workers_use_the_scan_knowledge(tmp_path: Path):
    for i in range(20):  # above PARALLEL_THRESHOLD, so worker processes analyse the files
        (tmp_path / f"app{i}.py").write_text(CUSTOM)
    (tmp_path / ".hackscan.yml").write_text(NOTE)
    config = load(tmp_path).with_overrides(jobs=2)
    assert _statuses(tmp_path, config) == {Status.CONFIRMED}
    assert _statuses(tmp_path, config.with_overrides(project_knowledge=False)) == {Status.CANDIDATE}


def test_outputs_record_the_knowledge_used(tmp_path: Path):
    (tmp_path / "app.py").write_text(CUSTOM)
    (tmp_path / ".hackscan.yml").write_text(NOTE)
    result = scan(tmp_path, load(tmp_path))
    data = _json(result, result.findings)
    assert data["tool"]["knowledge"] == {
        "version": knowledge.BUILTIN.version,
        "sha256": knowledge.BUILTIN.sha256,
        "project_notes": 1,
    }
    props = export_sarif(result)["runs"][0]["tool"]["driver"]["properties"]
    assert props["knowledgeSha256"] == knowledge.BUILTIN.sha256 and props["projectNotes"] == 1
    assert json.dumps(data)  # serialisable


def test_knowledge_file_is_packaged():
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    data_file = Path(knowledge.__file__).with_name("knowledge.json")
    assert data_file.is_file()
    assert "exclude" not in pyproject or "knowledge.json" not in pyproject


FORMAT_CALL = (
    "import subprocess\nfrom myframework import incoming\n\n"
    "parts = ['echo safe']\nincoming().format(parts)\nsubprocess.run(parts[0], shell=True)\n"
)
FORMAT_ATTR = (
    "import subprocess\nfrom myframework import incoming\n\n"
    "parts = ['echo safe']\nincoming.message.format(parts)\nsubprocess.run(parts[0], shell=True)\n"
)


@pytest.mark.parametrize(
    "code, value",
    [(FORMAT_CALL, "myframework.incoming"), (FORMAT_ATTR, "myframework.incoming.message")],
)
def test_a_noted_input_may_be_any_object_and_never_suppresses(tmp_path: Path, code, value):
    (tmp_path / "app.py").write_text(code)
    before = _statuses(tmp_path, HackScanConfig())
    (tmp_path / ".hackscan.yml").write_text(
        f"knowledge:\n  - type: source_name\n    value: {value}\n"
        "    rationale: r\n    evidence: e\n"
    )
    after = _statuses(tmp_path, load(tmp_path))
    assert Status.SUPPRESSED not in after and after, (before, after)


def test_unknown_keys_of_mixed_types_give_a_config_error(tmp_path: Path):
    (tmp_path / ".hackscan.yml").write_text(
        "knowledge:\n  - type: source_name\n    value: x\n    rationale: r\n"
        "    evidence: e\n    0: zero\n    typo: t\n"
    )
    with pytest.raises(ConfigError):
        load(tmp_path)
