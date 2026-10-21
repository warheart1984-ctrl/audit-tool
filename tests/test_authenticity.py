"""Authorship and completeness of ledger entries: signing (T1/T5), unhashed fields (T2),
anchor coverage, and concurrent writers."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

from audit_tool.ledger import Ledger
from audit_tool.models import Event

KEY = bytes(range(32))


def test_unexpected_top_level_field_is_flagged(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("case.create", {"id": "c"})
    entry = json.loads(ledger.path.read_text(encoding="utf-8"))
    entry["reviewer"] = "senior-compliance-officer"
    ledger.path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    assert any("unexpected field(s) reviewer" in p for p in ledger.verify())


def test_actor_is_covered_by_the_hash(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", actor="alice")
    ledger.append("case.create", {"id": "c"})
    entry = json.loads(ledger.path.read_text(encoding="utf-8"))
    assert entry["actor"] == "alice"
    entry["actor"] = "mallory"
    ledger.path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    assert any("modified after recording" in p for p in ledger.verify())


def test_signed_ledger_verifies_with_its_key(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key=KEY)
    ledger.append("case.create", {"id": "c"})
    ledger.append("event.add", {"id": "EVT-0001"})
    assert ledger.verify() == []


def test_append_without_the_key_after_signing_began_is_flagged(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("case.create", {"id": "c"})
    Ledger(path).append("event.add", {"id": "EVT-0002", "evidence_status": "verified"})  # no key
    problems = Ledger(path, key=KEY).verify()
    assert any("entry 2: unsigned entry after signing began" in p for p in problems)


def test_entry_signed_with_another_key_is_flagged(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key=KEY).append("case.create", {"id": "c"})
    Ledger(path, key=b"x" * 32).append("event.add", {"id": "EVT-0001"})
    assert any("entry 2: signature does not match" in p for p in Ledger(path, key=KEY).verify())


def test_unsigned_history_before_signing_is_allowed_but_counted(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path).append("case.create", {"id": "c"})
    Ledger(path, key=KEY).append("event.add", {"id": "EVT-0001"})
    signed = Ledger(path, key=KEY)
    assert signed.verify() == []
    assert signed.unsigned_prefix() == 1


def test_key_given_but_nothing_signed_is_flagged(tmp_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path).append("case.create", {"id": "c"})
    assert "no entry is signed with this key" in Ledger(path, key=KEY).verify()


def test_entries_after_an_anchor_are_counted(ws):
    case = ws.create_case("c", "t")
    anchored = case.ledger.head()
    case.add_event(Event(id="EVT-0001"))
    case.update_event("EVT-0001", {"notes": "x"}, "r")
    assert case.entries_after(anchored) == 2
    assert case.entries_after("f" * 64) is None


def _writer(path: str, n: int) -> None:
    ledger = Ledger(Path(path))
    for i in range(n):
        ledger.append("case.note", {"i": i})


def test_concurrent_writers_lose_nothing(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(str(path), 40)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(120)
    assert all(p.exitcode == 0 for p in procs)
    ledger = Ledger(path)
    assert len(ledger.entries(fresh=True)) == 160
    assert ledger.verify() == []
    assert not (tmp_path / "ledger.jsonl.lock").exists()
