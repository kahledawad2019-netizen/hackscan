from __future__ import annotations

import json

import pytest

from vulnhawk.core.models import (
    SCHEMA_VERSION,
    Evidence,
    Finding,
    Fix,
    FixEdit,
    Region,
    Severity,
    Status,
)


def test_severity_and_status_ranks():
    assert [s.rank for s in Severity] == [0, 1, 2, 3]
    assert Status.CONFIRMED.rank > Status.CANDIDATE.rank > Status.SUPPRESSED.rank


def test_region_defaults_and_validation():
    r = Region(path="a.py", start_line=3)
    assert r.end_line == 3
    with pytest.raises(ValueError):
        Region(path="a.py", start_line=0)
    with pytest.raises(ValueError):
        Region(path="a\\b.py", start_line=1)
    with pytest.raises(ValueError):
        Region(path="a.py", start_line=5, end_line=4)


def test_region_overlap():
    a = Region(path="a.py", start_line=1, end_line=5)
    assert a.overlaps(Region(path="a.py", start_line=5, end_line=9))
    assert not a.overlaps(Region(path="a.py", start_line=6))
    assert not a.overlaps(Region(path="b.py", start_line=1))


def test_suppression_reason_required_iff_suppressed(make_finding):
    with pytest.raises(ValueError):
        make_finding(status=Status.SUPPRESSED)
    with pytest.raises(ValueError):
        make_finding(suppression="taint:constant_input")
    make_finding(status=Status.SUPPRESSED, suppression="taint:constant_input")


def test_confidence_bounds(make_finding):
    with pytest.raises(ValueError):
        make_finding(confidence=101)


def test_roundtrip_through_json(make_finding):
    region = Region(path="app/db.py", start_line=10, start_column=5, end_column=40)
    f = make_finding(
        evidence=(Evidence("taint", "taint_step", "uid <- request.args", region),),
        fix=Fix("parameterize", (FixEdit(region, "cursor.execute(q, (uid,))"),), "template"),
    )
    data = json.loads(json.dumps(f.to_dict()))
    assert data["schema_version"] == SCHEMA_VERSION
    assert Finding.from_dict(data) == f


def test_from_dict_rejects_unknown_schema(make_finding):
    data = make_finding().to_dict()
    data["schema_version"] = 99
    with pytest.raises(ValueError):
        Finding.from_dict(data)
