"""Ed25519 entry signing: post-anchor appends need the private key, the public key
can verify but not forge, and verify catches forged, unsigned, stripped and
foreign-key entries once signing has begun."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from audit_tool.ledger import Ledger, key_id  # noqa: E402
from audit_tool.models import Event  # noqa: E402
from audit_tool.store import Case, Workspace  # noqa: E402

KEY = Ed25519PrivateKey.generate()
OTHER_KEY = Ed25519PrivateKey.generate()


@pytest.fixture
def signed_case(tmp_path):
    return Workspace(tmp_path / "cases", signer=KEY, actor="reviewer").create_case("c", "t")


def _forge_unsigned_append(case, event_id="EVT-9999"):
    """Append a chain-valid but unsigned entry, as someone without the key would."""
    Ledger(case.ledger.path).append(
        "event.add", Event(id=event_id, decision="Approved", evidence_status="verified").to_dict())


def test_signed_entries_verify_clean_with_the_key(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    assert signed_case.verify() == []
    entry = signed_case.ledger.entries()[-1]
    assert entry["actor"] == "reviewer" and entry["kid"] == key_id(KEY.public_key()) and "sig" in entry


def test_public_key_alone_verifies_but_cannot_sign(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    checker = Case(signed_case.dir, verify_key=KEY.public_key())
    assert checker.verify() == []
    assert checker.ledger.signer is None
    checker.ledger.append("event.add", Event(id="EVT-0002").to_dict())  # holder of the public key only
    assert any("unsigned entry after signing began" in p for p in checker.verify())


def test_case_ships_its_public_key(signed_case):
    assert (signed_case.dir / "signing-key.pub").exists()


def test_unsigned_append_after_signing_is_flagged(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    _forge_unsigned_append(signed_case)
    assert any("unsigned entry after signing began" in p for p in signed_case.verify())


def test_tampered_signature_is_flagged(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    lines = signed_case.ledger.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    entry["sig"] = ("00" if entry["sig"][:2] != "00" else "11") + entry["sig"][2:]
    lines[-1] = json.dumps(entry)
    signed_case.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("signature is invalid" in p for p in signed_case.verify())


def test_strip_all_signatures_is_flagged(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    lines = []
    for line in signed_case.ledger.path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        for k in ("sig", "kid", "actor"):
            entry.pop(k, None)
        lines.append(json.dumps(entry))
    signed_case.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems = signed_case.verify()
    # Removing kid/actor changes what the hash covered, and no entry is signed any more.
    assert any("no entry is signed" in p for p in problems)


def _strip_sig_only(ledger_path, index: int) -> None:
    """Delete one entry's `sig` and nothing else, keeping its `kid` and `actor`."""
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[index])
    del entry["sig"]
    lines[index] = json.dumps(entry, ensure_ascii=False)
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.mark.parametrize("index", [0, 1])  # the earliest entry (the reported bypass) and a middle one
def test_removing_one_signature_but_keeping_its_kid_fails(signed_case, index):
    # Found by the independent verifier (PR #1). The older strip test removed sig, kid and
    # actor together, which breaks the hash, so this exact edit was never tried.
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    anchor = signed_case.ledger.anchor()
    _strip_sig_only(signed_case.ledger.path, index)
    for checker in (signed_case, Case(signed_case.dir), Case(signed_case.dir, verify_key=KEY.public_key())):
        problems = checker.verify(expect_head=anchor, exact=True)
        assert any(f"entry {index + 1}: signature removed" in p for p in problems), problems


def test_a_stripped_entry_is_not_counted_as_unsigned_history(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    _strip_sig_only(signed_case.ledger.path, 0)
    assert signed_case.ledger.unsigned_prefix() == 0


def test_stripped_signature_through_the_cli(cli, tmp_path):
    key = tmp_path / "k.key"
    cli("keygen", str(key))
    cli("--key-file", str(key), "new", "c", "--title", "t")
    code, out = cli("--key-file", str(key), "add", "c", "--set", "decision=Denied")
    anchor = out.split("Ledger anchor: ")[1].split()[0]
    _strip_sig_only(tmp_path / "cases" / "c" / "ledger.jsonl", 0)
    code, out = cli("--key-file", str(key), "verify", "c", "--expect", anchor, "--exact")
    assert code == 2 and "signature removed" in out
    assert cli("check", "c")[0] == 2  # no key needed to notice


def test_entry_signed_with_another_key_is_flagged(tmp_path):
    victim = Workspace(tmp_path / "cases", signer=KEY).create_case("c", "t")
    Ledger(victim.ledger.path, signer=OTHER_KEY).append(
        "event.add", Event(id="EVT-9999", decision="Approved", evidence_status="verified").to_dict())
    assert any("signed by another key" in p for p in victim.verify())


def test_unsigned_legacy_prefix_then_signed_history_is_clean(tmp_path):
    case = Workspace(tmp_path / "cases").create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Declined"))  # unsigned history
    case = Workspace(tmp_path / "cases", signer=KEY).open_case("c")
    case.add_event(Event(id="EVT-0002", decision="Declined"))  # signing starts here
    assert case.ledger.unsigned_prefix() == 2
    assert case.verify() == []


def test_actor_and_kid_are_committed_to_the_hash(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    for field, value in (("actor", "an-impostor"), ("kid", "0" * 16)):
        lines = signed_case.ledger.path.read_text(encoding="utf-8").splitlines()
        original = lines[-1]
        entry = json.loads(original)
        entry[field] = value
        lines[-1] = json.dumps(entry)
        signed_case.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert any("modified after recording" in p for p in signed_case.verify())
        lines[-1] = original
        signed_case.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_key_id_is_stable_and_distinct():
    assert key_id(KEY.public_key()) == key_id(KEY.public_key())
    assert key_id(KEY.public_key()) != key_id(OTHER_KEY.public_key())


# --- Anchors with positions -------------------------------------------------------

def test_anchor_does_not_cover_later_entries_unless_exact(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    anchor = signed_case.ledger.anchor()
    signed_case.add_event(Event(id="EVT-0002", decision="Declined"))
    assert signed_case.entries_after(anchor) == 1
    assert signed_case.verify(expect_head=anchor) == []
    assert any("--exact requires" in p for p in signed_case.verify(expect_head=anchor, exact=True))


def test_exact_anchor_catches_tail_truncation(tmp_path):
    case = Workspace(tmp_path / "cases").create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Declined"))
    case.update_event("EVT-0001", {"notes": "important later fact"}, "r")
    anchor = case.ledger.anchor()
    lines = case.ledger.path.read_text(encoding="utf-8").splitlines()
    case.ledger.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert any("not in this ledger at its recorded position" in p
               for p in case.verify(expect_head=anchor, exact=True))


def test_anchor_must_be_at_its_recorded_position(tmp_path):
    case = Workspace(tmp_path / "cases").create_case("c", "t")
    case.add_event(Event(id="EVT-0001"))
    seq, digest = case.ledger.anchor().split(":")
    assert case.verify(expect_head=f"{seq}:{digest}") == []
    assert any("recorded position" in p for p in case.verify(expect_head=f"{int(seq) + 1}:{digest}"))


def test_exact_needs_a_sequence_number(tmp_path):
    case = Workspace(tmp_path / "cases").create_case("c", "t")
    assert any("<seq>:<hash>" in p for p in case.verify(expect_head=case.ledger.head(), exact=True))
