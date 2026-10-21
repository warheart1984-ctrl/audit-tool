"""Malformed entries (T3), self-attested confirmation (T5) and case-id aliasing."""

from __future__ import annotations

import pytest

from audit_tool.models import Event
from audit_tool.report import render_markdown
from audit_tool.rules import audit


@pytest.mark.parametrize("kind,payload", [
    ("event.update", [1, 2]),
    ("event.update", "x"),
    ("event.update", {"id": "EVT-0001", "changes": [1]}),
    ("event.update", {"id": "EVT-0001", "changes": {"notes": 5}}),
    ("event.update", {"id": ["EVT-0001"], "changes": {}}),
    ("artifact.link", {"event_id": "EVT-0001", "artifact": "x"}),
    ("artifact.link", {"event_id": "EVT-0001", "artifact": {"stored_path": 1}}),
    ("event.add", [1]),
    ("event.add", {"id": 7}),
    ("event.add", {"id": "EVT-0002", "decision": 5}),
    ("event.add", {"id": "EVT-0003", "origin": "confirmed"}),
])
def test_malformed_payloads_are_reported_not_crashed_on(ws, kind, payload):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Denied"))
    case.ledger.append(kind, payload)
    problems = case.verify()
    assert any("ignored" in p for p in problems), problems
    audit(case.events())
    render_markdown(case)


def test_confirmation_cannot_be_claimed_at_creation(ws):
    case = ws.create_case("c", "t")
    case.ledger.append("event.add", Event(id="EVT-0001", reason="x", origin={"reason": "confirmed"}).to_dict())
    events, problems = case.replay()
    assert events["EVT-0001"].origin == {}
    assert any("confirmation claimed at creation" in p for p in problems)


def test_extracted_origin_survives_creation(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", reason="x", origin={"reason": "extracted"}))
    assert case.events()["EVT-0001"].origin == {"reason": "extracted"}
    assert case.verify() == []


@pytest.mark.parametrize("case_id", ["x.", "x-.", "CON", "nul", "Com1", "aux.txt", "lpt9.log"])
def test_case_ids_that_alias_or_are_reserved_on_windows_are_rejected(ws, case_id):
    with pytest.raises(ValueError):
        ws.create_case(case_id, "t")


def test_replay_does_not_mutate_cached_entries(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", origin={"reason": "extracted"}),
                   {"stored_path": "evidence/a", "sha256": "0"})
    case.update_event("EVT-0001", {"reason": "y"}, "r")
    first = case.events()["EVT-0001"]
    second = case.events()["EVT-0001"]
    assert len(second.artifacts) == 1
    assert second.origin == first.origin == {"reason": "confirmed"}
