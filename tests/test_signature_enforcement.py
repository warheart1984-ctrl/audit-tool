"""Every command checks signatures, not just `verify` (PR #1, Medium finding 2).

Before: `check`, `show`, `report` and `list` only checked signatures if a key was
passed, so a ledger with intact hashes but a forged signature got a clean audit.
Now the case's own `signing-key.pub` is used by default, and a signed case whose
key file is missing or unreadable fails closed.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("cryptography")


@pytest.fixture
def signed(cli, tmp_path):
    key = tmp_path / "k.key"
    cli("keygen", str(key))
    cli("--key-file", str(key), "new", "c", "--title", "t")
    cli("--key-file", str(key), "add", "c", "--set", "decision=Denied")
    return key, tmp_path / "cases" / "c"


def _forge_last_signature(case_dir):
    """Change one hex digit of the last signature; the hash chain stays intact."""
    path = case_dir / "ledger.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    entry["sig"] = ("1" if entry["sig"][0] != "1" else "2") + entry["sig"][1:]
    lines[-1] = json.dumps(entry, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_forged_signature_fails_every_command_without_passing_a_key(cli, signed):
    _, case_dir = signed
    _forge_last_signature(case_dir)
    code, out = cli("verify", "c")
    assert code == 2 and "signature is invalid" in out
    for args in (("check", "c"), ("show", "c", "EVT-0001")):
        code, out = cli(*args)
        assert code == 2 and "signature is invalid" in out, args
    code, out = cli("report", "c")
    assert code == 2 and "WARNING: INTEGRITY FAILED" in out.split("## Summary")[0]
    code, out = cli("list")
    assert "INTEGRITY FAILED" in out


def test_deleting_the_case_public_key_does_not_hide_a_forgery(cli, signed):
    _, case_dir = signed
    _forge_last_signature(case_dir)
    (case_dir / "signing-key.pub").unlink()
    code, out = cli("check", "c")
    assert code == 2 and "signatures can't be checked" in out and "signing-key.pub is missing" in out


def test_unreadable_case_public_key_fails_closed(cli, signed):
    _, case_dir = signed
    (case_dir / "signing-key.pub").write_text("not a key", encoding="utf-8")
    code, out = cli("check", "c")
    assert code == 2 and "could not be loaded" in out


def test_intact_signed_case_still_passes_without_a_key(cli, signed):
    assert cli("check", "c")[0] == 0
    code, out = cli("verify", "c")
    assert code == 0 and "public key stored in the case folder" in out


@pytest.mark.parametrize("args", [("add", "c", "--set", "decision=Denied"),
                                  ("edit", "c", "EVT-0001", "--set", "notes=x")])
def test_writing_to_a_signed_case_without_the_key_is_refused(cli, signed, args):
    _, case_dir = signed
    before = (case_dir / "ledger.jsonl").read_bytes()
    code, out = cli(*args)
    assert code == 1 and "is signed; pass --key-file" in out
    assert (case_dir / "ledger.jsonl").read_bytes() == before
    assert cli("verify", "c")[0] == 0


def test_writing_with_the_key_still_works(cli, signed):
    key, _ = signed
    assert cli("--key-file", str(key), "edit", "c", "EVT-0001", "--set", "notes=x")[0] == 0
    assert cli("check", "c")[0] == 0
