"""Entry signing (T1): post-anchor appends need a key, and verify must catch
forged, unsigned and stripped entries once signing has begun."""

from __future__ import annotations

import json

import pytest

from audit_tool.ledger import Ledger, key_fingerprint
from audit_tool.models import Event
from audit_tool.store import Workspace

KEY = b"k" * 32
OTHER_KEY = b"x" * 32


@pytest.fixture
def signed_case(tmp_path):
    return Workspace(tmp_path / "cases", key=KEY, actor="reviewer").create_case("c", "t")


def _forge_unsigned_append(case, event_id="EVT-9999"):
    """Append a chain-valid but unsigned entry, as someone without the key would."""
    Ledger(case.ledger.path).append(
        "event.add",
        Event(id=event_id, decision="Approved", reason="fabricated",
              evidence_status="verified").to_dict())


def test_signed_entries_verify_clean_with_the_key(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    assert signed_case.verify() == []
    entry = signed_case.ledger.entries()[-1]
    assert entry["actor"] == "reviewer"
    assert "sig" in entry


def test_unsigned_append_after_signing_is_flagged(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    _forge_unsigned_append(signed_case)
    problems = signed_case.verify()
    assert any("unsigned entry after signing began" in p for p in problems)


def test_strip_all_signatures_is_flagged(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    lines = []
    for line in signed_case.ledger.path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        entry.pop("sig", None)
        entry.pop("actor", None)
        lines.append(json.dumps(entry))
    signed_case.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("no entry is signed" in p for p in signed_case.verify())


def test_entry_signed_with_another_key_is_flagged(tmp_path):
    victim = Workspace(tmp_path / "cases", key=KEY).create_case("c", "t")
    victim.add_event(Event(id="EVT-0001", decision="Declined"))
    # Attacker holding a *different* key appends a properly signed entry.
    Ledger(victim.ledger.path, key=OTHER_KEY).append(
        "event.add", Event(id="EVT-9999", decision="Approved", evidence_status="verified").to_dict())
    problems = victim.verify()
    assert any("signature does not match this key" in p for p in problems)


def test_unsigned_legacy_prefix_then_signed_history_is_clean(tmp_path):
    ws_unsigned = Workspace(tmp_path / "cases")
    case = ws_unsigned.create_case("c", "t")
    case.add_event(Event(id="EVT-0001", decision="Declined"))  # unsigned history
    assert case.ledger.unsigned_prefix() == 2

    keyed = Workspace(tmp_path / "cases", key=KEY)
    case = keyed.open_case("c")
    case.add_event(Event(id="EVT-0002", decision="Declined"))  # signing starts here
    assert case.ledger.unsigned_prefix() == 2
    assert case.verify() == []


def test_verify_without_a_key_reports_signed_ledger_cant_be_checked(cli, tmp_path, capsys):
    # Signed via API; CLI without --key-file can only note the gap, not check it.
    keyed = Workspace(tmp_path / "cases", key=KEY)
    keyed.create_case("c", "t")
    code, out = cli("verify", "c")
    assert code == 0
    assert "pass --key-file to check the signatures" in out


def test_anchor_does_not_cover_later_entries_entries_after_counts_them(signed_case):
    """Regression note for the truncation attack: an anchor only proves the
    prefix. Anything appended after it must be counted and reviewed."""
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    anchor = signed_case.ledger.head()
    signed_case.add_event(Event(id="EVT-0002", decision="Declined"))
    assert signed_case.entries_after(anchor) == 1
    assert signed_case.verify(expect_head=anchor) == []
    # Entries deleted from the tail leave the anchor intact -- the anchor
    # alone cannot notice. Re-anchor after every session.
    lines = signed_case.ledger.path.read_text(encoding="utf-8").splitlines()
    signed_case.ledger.path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    assert signed_case.entries_after(anchor) == 0
    assert signed_case.verify(expect_head=anchor) == []  # prefix still verifies; see README limits


def test_actor_is_committed_to_the_hash(signed_case):
    signed_case.add_event(Event(id="EVT-0001", decision="Declined"))
    lines = signed_case.ledger.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    entry["actor"] = "an-impostor"
    lines[-1] = json.dumps(entry)
    signed_case.ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert any("modified after recording" in p for p in signed_case.verify())


def test_key_fingerprint_is_stable_and_short():
    assert key_fingerprint(KEY) == key_fingerprint(KEY)
    assert key_fingerprint(KEY) != key_fingerprint(OTHER_KEY)
