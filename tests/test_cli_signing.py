"""Signing, anchors and confirmation-by-edit through the real CLI."""

from __future__ import annotations

import re

import pytest

from audit_tool.ledger import Ledger

ANCHOR = re.compile(r"Ledger anchor: (\d+:[0-9a-f]{64})")


def test_signed_workflow_detects_unkeyed_append(cli, tmp_path):
    pytest.importorskip("cryptography")
    key = tmp_path / "keys" / "audit.key"
    code, out = cli("keygen", str(key))
    assert code == 0 and key.exists() and (tmp_path / "keys" / "audit.key.pub").exists()
    kid = re.search(r"key id ([0-9a-f]{16})", out).group(1)
    assert cli("--key-file", str(key), "--actor", "me", "new", "c", "--title", "t")[0] == 0
    code, out = cli("--key-file", str(key), "verify", "c")
    assert code == 0 and f"signed by key {kid}" in out

    Ledger(tmp_path / "cases" / "c" / "ledger.jsonl").append("event.add", {"id": "EVT-0001"})
    code, out = cli("--key-file", str(key), "verify", "c")
    assert code == 2 and "unsigned entry after signing began" in out


def test_third_party_verifies_with_public_key_only(cli, tmp_path):
    pytest.importorskip("cryptography")
    key = tmp_path / "audit.key"
    cli("keygen", str(key))
    cli("--key-file", str(key), "new", "c", "--title", "t")
    code, out = cli("--public-key", str(tmp_path / "audit.key.pub"), "verify", "c")
    assert code == 0 and "signed by key" in out
    # Without any key, the copy shipped in the case folder is used, with a warning to compare the id.
    code, out = cli("verify", "c")
    assert code == 0 and "public key stored in the case folder" in out


def test_key_inside_cases_folder_is_refused(cli, tmp_path):
    code, out = cli("keygen", str(tmp_path / "cases" / "audit.key"))
    assert code == 1 and "outside the cases folder" in out


def test_keygen_refuses_to_overwrite(cli, tmp_path):
    pytest.importorskip("cryptography")
    key = tmp_path / "audit.key"
    cli("keygen", str(key))
    original = key.read_bytes()
    code, out = cli("keygen", str(key))
    assert code == 1 and key.read_bytes() == original


def test_verify_expect_reports_entries_added_after_the_anchor(cli):
    code, out = cli("new", "c", "--title", "t")
    anchor = ANCHOR.search(out).group(1)
    cli("add", "c", "--set", "decision=Denied")
    code, out = cli("verify", "c", "--expect", anchor)
    assert code == 0 and "2 entries were added after that anchor and are NOT covered" in out
    code, out = cli("verify", "c", "--expect", anchor, "--exact")
    assert code == 2 and "--exact requires the anchor to be the newest entry" in out


def test_exact_anchor_catches_truncation_through_cli(cli, tmp_path):
    cli("new", "c", "--title", "t")
    code, out = cli("add", "c", "--set", "decision=Denied")
    anchor = ANCHOR.search(out).group(1)
    ledger = tmp_path / "cases" / "c" / "ledger.jsonl"
    ledger.write_text("\n".join(ledger.read_text().splitlines()[:-1]) + "\n")
    code, out = cli("verify", "c", "--expect", anchor, "--exact")
    assert code == 2 and "INTEGRITY FAILED" in out


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
