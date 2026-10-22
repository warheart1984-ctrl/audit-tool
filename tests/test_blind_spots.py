"""Tests written to kill mutants that survived the first mutation run (tools/mutation).

Each test names the planted defect it exists to catch. Before these, the suite
passed with that defect in place.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from audit_tool.ledger import Ledger, _entry_hash
from audit_tool.models import Event
from audit_tool.rules import audit, flag
from audit_tool.secure import restrict_dir, windows_acl_entries


def _findings(ev: Event) -> dict[str, tuple[str, str]]:
    return {f.rule: (f.severity, f.statement) for f in audit({ev.id: ev})}


# L1: chain-link check. Only `prev` catches a middle entry replaced by a forged
# entry whose own hash and sequence number are recomputed to look valid.
def test_forged_middle_entry_with_recomputed_hash_breaks_the_chain(tmp_path):
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("case.create", {"id": "c"})
    ledger.append("event.add", {"id": "EVT-0001", "decision": "Denied"})
    ledger.append("event.update", {"id": "EVT-0001", "changes": {"notes": "x"}, "reason": "r"})
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[1])
    forged["payload"]["decision"] = "Approved"
    forged["prev"] = "f" * 64  # point it anywhere; its own hash is made consistent below
    forged["hash"] = _entry_hash(forged)
    lines[1] = json.dumps(forged)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems = ledger.verify()
    assert not any("modified after recording" in p for p in problems)  # entry 2 is self-consistent ...
    assert any("entry 2: chain broken" in p for p in problems)  # ... only the link gives it away
    assert any("entry 3: chain broken" in p for p in problems)


# S5: the case-folder confinement check is the layer behind the case-id rules.
# A valid id whose folder is a link or junction elsewhere must still be refused.
def test_case_folder_linked_outside_the_workspace_is_refused(ws, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    Ledger(outside / "ledger.jsonl").append("case.create", {"id": "victim"})
    ws.root.mkdir(parents=True)
    link = ws.root / "c"
    if sys.platform == "win32":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
        if r.returncode:
            pytest.skip("could not create a junction")
    else:
        os.symlink(outside, link)
    with pytest.raises(ValueError, match="does not resolve to its own folder"):
        ws.open_case("c")


# R2: the PASS gate needs a confirmed rule (policy or code), not just reason + evidence.
def test_gate_fails_when_only_the_rule_is_missing():
    ev = Event(id="EVT-0001", decision="Denied", reason="r", supporting_evidence="e")
    ev.origin.update(reason="confirmed", supporting_evidence="confirmed")
    assert flag(ev) == "AUDIT FLAG"
    ev.status_code = "R16"
    ev.origin["status_code"] = "extracted"
    assert flag(ev) == "AUDIT FLAG"  # an extracted code doesn't count either
    ev.origin["status_code"] = "confirmed"
    assert flag(ev) == "PASS"


# R3: no review on record must produce a HUMAN finding, high when the decision was automated.
def test_human_finding_when_no_review_is_on_record():
    ev = Event(id="EVT-0001", decision="Denied")
    assert _findings(ev)["HUMAN"] == ("medium", "No human review record has been provided.")
    ev.automated = "yes"
    assert _findings(ev)["HUMAN"][0] == "high"
    ev.human_involved = "no"
    assert _findings(ev)["HUMAN"] == ("high", "No human review record has been provided.")


# R5: no appeal path on record must produce a high APPEAL finding.
def test_appeal_finding_when_none_was_disclosed():
    assert _findings(Event(id="EVT-0001", decision="Denied"))["APPEAL"] == ("high", "No appeal path was disclosed.")


# R6: a decision with no reason, or one marked not reproducible, must produce REPRO.
def test_repro_finding_without_a_reason_or_when_not_reproducible():
    ev = Event(id="EVT-0001", decision="Denied")
    assert _findings(ev)["REPRO"][0] == "high"
    assert "No reason was given" in _findings(ev)["REPRO"][1]
    ev.reason = "policy"
    assert "REPRO" not in _findings(ev)
    ev.reproducible = "no"
    assert "cannot be explained or reproduced from the reason given" in _findings(ev)["REPRO"][1]


# Z1: restrict_dir must remove inherited access itself. Tested on a folder made
# with ordinary permissions, so Python's own owner-only mkdir can't mask a regression.
@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_restrict_dir_removes_inherited_access_on_an_ordinary_folder(tmp_path):
    from audit_tool.secure import _system_tool

    # Don't rely on the machine's temp-folder ACL (CI runners differ): give the
    # parent an inheritable "Users: read" entry so the child certainly inherits it.
    parent = tmp_path / "parent"
    os.mkdir(parent)
    subprocess.run([_system_tool("icacls.exe"), str(parent), "/grant", "*S-1-5-32-545:(OI)(CI)RX"],
                   capture_output=True, check=True)
    folder = parent / "plain"
    os.mkdir(folder)  # default mode: inherits the parent's ACL
    before = windows_acl_entries(folder)
    assert "BUILTIN\\Users:(I)" in before
    restrict_dir(folder)
    acl = windows_acl_entries(folder)
    assert "(I)" not in acl
    assert "Authenticated Users" not in acl and "BUILTIN\\Users" not in acl


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_restrict_dir_sets_0700_on_an_ordinary_folder(tmp_path):
    folder = tmp_path / "plain"
    os.mkdir(folder, 0o755)
    restrict_dir(folder)
    assert (folder.stat().st_mode & 0o777) == 0o700
