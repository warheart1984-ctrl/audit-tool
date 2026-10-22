"""A case's ledger must start with its case.create entry, exactly once.

Found while reproducing the lone-surrogate finding: an emptied ledger.jsonl
verified as "OK: ledger chain intact" and `check` reported "No findings". Each
bad shape below is built as a hash-valid chain, so only this rule can catch it.
"""

from __future__ import annotations

import pytest

from audit_tool.ledger import Ledger


def test_empty_ledger_fails(ws):
    case = ws.create_case("c", "t")
    case.ledger.path.write_text("", encoding="utf-8")
    assert any("ledger is empty" in p for p in case.verify())


def test_chain_that_starts_mid_story_fails(ws):
    case = ws.create_case("c", "t")
    case.ledger.path.unlink()
    Ledger(case.ledger.path).append("event.add", {"id": "EVT-0001", "decision": "Approved"})
    assert case.ledger.verify() == []  # the chain itself is valid ...
    assert any("entry 1 is 'event.add', not case.create" in p for p in case.verify())  # ... the case isn't


def test_second_case_create_fails(ws):
    case = ws.create_case("c", "original title")
    Ledger(case.ledger.path).append("case.create", {"id": "c", "title": "re-titled"})
    assert case.ledger.verify() == []
    assert any("entry 2: case.create may only be entry 1" in p for p in case.verify())


def test_a_normal_case_still_verifies(ws):
    assert ws.create_case("c", "t").verify() == []


@pytest.mark.parametrize("args", [("verify", "c"), ("check", "c")])
def test_empty_ledger_fails_through_the_cli(cli, tmp_path, args):
    cli("new", "c", "--title", "t")
    (tmp_path / "cases" / "c" / "ledger.jsonl").write_text("", encoding="utf-8")
    code, out = cli(*args)
    assert code == 2 and "ledger is empty" in out
