"""Case workspace: id confinement (F1), tolerant replay (F3), evidence folder audit (F6)."""

from __future__ import annotations

import os

import pytest

from audit_tool.ledger import Ledger
from audit_tool.models import Event


@pytest.mark.parametrize("case_id", ["..", ".", "../x", "a/b", "a\\b", "/abs", "C:x", "", ".hidden", "a..b"])
def test_create_case_rejects_ids_that_could_leave_the_workspace(ws, tmp_path, case_id):
    with pytest.raises(ValueError):
        ws.create_case(case_id, "t")
    assert not (tmp_path / "ledger.jsonl").exists()
    assert not (ws.root / "ledger.jsonl").exists()


def test_open_case_rejects_absolute_path_to_another_ledger(ws, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    Ledger(outside / "ledger.jsonl").append("case.create", {"id": "victim"})
    with pytest.raises(ValueError):
        ws.open_case(str(outside))
    with pytest.raises(ValueError):
        ws.open_case("../outside")


def test_valid_case_ids_still_work(ws):
    case = ws.create_case("bank-2026.10_a", "t")
    assert ws.open_case("bank-2026.10_a").dir == case.dir


def test_update_to_unknown_event_is_reported_not_raised(ws):
    case = ws.create_case("c", "t")
    case.ledger.append("event.update", {"id": "EVT-0099", "changes": {"notes": "x"}, "reason": "r"})
    case.ledger.append("artifact.link", {"event_id": "EVT-0042", "artifact": {}})
    events, problems = case.replay()
    assert events == {}
    assert any("EVT-0099" in p for p in problems)
    assert any("EVT-0042" in p for p in problems)
    assert any("EVT-0099" in p for p in case.verify())


def test_forged_update_cannot_set_non_editable_fields(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Denied"))
    case.ledger.append("event.update", {"id": "EVT-0001", "changes": {"artifacts": [{"x": 1}], "origin": {}},
                                        "reason": "forged"})
    events, problems = case.replay()
    assert events["EVT-0001"].artifacts == []
    assert sum("non-editable" in p for p in problems) == 2


def test_duplicate_event_id_is_reported_and_first_wins(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Denied"))
    case.ledger.append("event.add", Event(id="EVT-0001", decision="Approved").to_dict())
    events, problems = case.replay()
    assert events["EVT-0001"].decision == "Denied"
    assert any("duplicate event id EVT-0001" in p for p in problems)


def test_next_event_id_is_never_reused(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001"))
    case.ledger.append("event.add", Event(id="EVT-0007").to_dict())
    assert case.next_event_id() == "EVT-0008"


def test_unrecorded_file_in_evidence_folder_fails_verify(ws, tmp_path):
    case = ws.create_case("c", "t")
    src = tmp_path / "letter.txt"
    src.write_text("Your account was restricted.")
    case.add_event(Event(id="EVT-0001"), case.store_artifact(src))
    assert case.verify() == []
    (case.evidence_dir / "decoy.txt").write_text("planted")
    assert any("decoy.txt" in p and "not recorded" in p for p in case.verify())


def test_recorded_path_outside_evidence_folder_fails_verify(ws, tmp_path):
    case = ws.create_case("c", "t")
    secret = tmp_path / "secret.txt"
    secret.write_text("x")
    case.add_event(Event(id="EVT-0001"))
    case.ledger.append("artifact.link", {"event_id": "EVT-0001",
                                         "artifact": {"stored_path": "../../secret.txt", "sha256": "0" * 64}})
    assert any("outside the evidence folder" in p for p in case.verify())


def test_symlink_in_evidence_folder_fails_verify(ws, tmp_path):
    case = ws.create_case("c", "t")
    target = tmp_path / "target.txt"
    target.write_text("x")
    case.evidence_dir.mkdir(parents=True)
    try:
        os.symlink(target, case.evidence_dir / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks is not permitted here")
    assert any("symbolic link" in p for p in case.verify())


def test_unreadable_ledger_line_is_reported_by_verify(ws):
    case = ws.create_case("c", "t")
    with case.ledger.path.open("a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    problems = case.verify()
    assert len(problems) == 1 and "not valid JSON" in problems[0]
