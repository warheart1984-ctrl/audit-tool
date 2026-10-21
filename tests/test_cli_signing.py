"""Signing, anchor coverage and confirmation-by-edit through the real CLI."""

from __future__ import annotations

import re

from audit_tool.ledger import Ledger


def test_signed_workflow_detects_unkeyed_append(cli, tmp_path):
    key = tmp_path / "keys" / "audit.key"
    code, out = cli("keygen", str(key))
    assert code == 0 and key.exists()
    assert cli("--key-file", str(key), "--actor", "me", "new", "c", "--title", "t")[0] == 0
    code, out = cli("--key-file", str(key), "verify", "c")
    assert code == 0 and "signed with key" in out

    Ledger(tmp_path / "cases" / "c" / "ledger.jsonl").append("event.add", {"id": "EVT-0001"})
    code, out = cli("--key-file", str(key), "verify", "c")
    assert code == 2 and "unsigned entry after signing began" in out


def test_key_inside_cases_folder_is_refused(cli, tmp_path):
    code, out = cli("keygen", str(tmp_path / "cases" / "audit.key"))
    assert code == 1 and "outside the cases folder" in out


def test_keygen_refuses_to_overwrite(cli, tmp_path):
    key = tmp_path / "audit.key"
    cli("keygen", str(key))
    original = key.read_text()
    code, out = cli("keygen", str(key))
    assert code == 1 and key.read_text() == original


def test_verify_expect_reports_entries_added_after_the_anchor(cli):
    code, out = cli("new", "c", "--title", "t")
    head = re.search(r"Ledger head: ([0-9a-f]{64})", out).group(1)
    cli("add", "c", "--set", "decision=Denied")
    code, out = cli("verify", "c", "--expect", head)
    assert code == 0 and "2 entries were added after that head and are NOT covered" in out


def test_hand_entered_and_source_facts_are_confirmed_by_edits(cli, tmp_path):
    cli("new", "c", "--title", "t")
    assert cli("add", "c", "--set", "decision=Denied", "--set", "reason=Policy 4")[0] == 0
    f = tmp_path / "letter.txt"
    f.write_text("Your account has been restricted.")
    cli("ingest", "c", str(f), "--source", "Example Bank")
    code, out = cli("show", "c", "EVT-0001")
    assert "Policy 4  (confirmed)" in out
    code, out = cli("show", "c", "EVT-0002")
    assert "Example Bank  (confirmed)" in out
    assert cli("verify", "c")[0] == 0
