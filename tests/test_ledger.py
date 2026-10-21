"""Hash chain and head anchoring (F2)."""

from __future__ import annotations

import json

from audit_tool.ledger import GENESIS, Ledger
from audit_tool.models import Event


def test_editing_a_recorded_entry_breaks_the_chain(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("case.create", {"id": "c"})
    ledger.append("event.add", {"id": "EVT-0001", "decision": "Denied"})
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["payload"]["decision"] = "Approved"
    lines[1] = json.dumps(entry)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("modified after recording" in p for p in ledger.verify())


def test_whole_ledger_rewrite_is_caught_by_an_anchored_head(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Denied", evidence_status="unverified"))
    anchored = case.ledger.head()

    # Replace the file with a fresh, internally consistent chain.
    case.ledger.path.unlink()
    forged = Ledger(case.ledger.path)
    forged.append("case.create", {"id": "c", "title": "t"})
    forged.append("event.add", Event(id="EVT-0001", decision="Denied", evidence_status="verified").to_dict())

    assert case.verify() == []  # the chain alone can't see this ...
    problems = case.verify(expect_head=anchored)  # ... the saved head can
    assert any("anchored head" in p for p in problems)


def test_anchor_still_verifies_after_later_appends(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001"))
    anchored = case.ledger.head()
    case.update_event("EVT-0001", {"notes": "added later"}, "review")
    assert case.ledger.head() != anchored
    assert case.verify(expect_head=anchored) == []


def test_head_of_empty_ledger_is_genesis(tmp_path):
    assert Ledger(tmp_path / "none.jsonl").head() == GENESIS


def test_contains_rejects_short_or_malformed_hashes(ws):
    case = ws.create_case("c", "t")
    head = case.ledger.head()
    assert case.ledger.contains(head)
    assert case.ledger.contains(head.upper())
    assert not case.ledger.contains(head[:12])
    assert not case.ledger.contains("")
