"""Completeness of ledger entries: unhashed fields (T2), actor in the hash, anchor
coverage, and concurrent writers. Signing itself is tested in test_signing.py."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path

from audit_tool.ledger import Ledger
from audit_tool.models import Event


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
