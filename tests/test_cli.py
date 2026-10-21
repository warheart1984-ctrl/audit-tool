"""End to end through the real CLI: traversal (F1), anchoring (F2), replay (F3), orphans (F6)."""

from __future__ import annotations

import re

from audit_tool.ledger import Ledger


def test_cli_rejects_traversal_case_id(cli, tmp_path):
    code, out = cli("new", "..", "--title", "t")
    assert code == 1 and "Case id" in out
    assert not (tmp_path / "ledger.jsonl").exists()


def test_file_with_no_adverse_decisions_is_not_left_in_evidence(cli, tmp_path):
    cli("new", "c", "--title", "t")
    f = tmp_path / "ok.csv"
    f.write_text("Date,Status\n2026-01-01,Posted\n")
    code, out = cli("ingest", "c", str(f))
    assert code == 0 and "not stored" in out
    assert not (tmp_path / "cases" / "c" / "evidence").exists()
    code, out = cli("verify", "c")
    assert code == 0, out


def test_mutations_print_head_and_verify_expect_catches_rewrite(cli, tmp_path):
    code, out = cli("new", "c", "--title", "t")
    head = re.search(r"Ledger head: ([0-9a-f]{64})", out).group(1)
    code, out = cli("head", "c")
    assert out.strip() == head

    code, out = cli("verify", "c", "--expect", head)
    assert code == 0 and "anchored head" in out

    ledger = tmp_path / "cases" / "c" / "ledger.jsonl"
    ledger.unlink()
    Ledger(ledger).append("case.create", {"id": "c", "title": "forged"})
    code, out = cli("verify", "c")
    assert code == 0 and "can't rule out" in out  # honest about the limit
    code, out = cli("verify", "c", "--expect", head)
    assert code == 2 and "INTEGRITY FAILED" in out


def test_verify_reports_bad_reference_instead_of_crashing(cli, tmp_path):
    cli("new", "c", "--title", "t")
    Ledger(tmp_path / "cases" / "c" / "ledger.jsonl").append(
        "event.update", {"id": "EVT-0099", "changes": {"notes": "x"}, "reason": "r"})
    code, out = cli("verify", "c")
    assert code == 2 and "unknown event EVT-0099" in out
    code, out = cli("report", "c")
    assert code == 0 and "unknown event EVT-0099" in out
