"""Origin-weighted findings (T4): extracted text must not clear findings or the gate.

Extraction runs on documents the audited party wrote, so an extracted value can
only downgrade a finding to "claimed, unconfirmed" -- clearing requires a
person's confirmation (an `event.update`, i.e. `audit edit`).
"""

from __future__ import annotations

import pytest

from audit_tool.ingest import ingest_file
from audit_tool.models import Event
from audit_tool.rules import audit, flag


def _event(**fields) -> Event:
    ev = Event(id="EVT-0001", decision="Declined")
    for name, value in fields.items():
        setattr(ev, name, value)
    return ev


def _extracted(ev: Event, *names: str) -> Event:
    for name in names:
        ev.origin[name] = "extracted"
    return ev


def _confirmed(ev: Event, *names: str) -> Event:
    for name in names:
        ev.origin[name] = "confirmed"
    return ev


def _finding(ev: Event, rule: str):
    return next((f for f in audit({ev.id: ev}) if f.rule == rule), None)


@pytest.mark.parametrize("field,value,rule", [
    ("human_involved", "yes", "HUMAN"),
    ("policy_cited", "Section 12.3", "RULE"),
    ("appeal_path", "the Financial Ombudsman", "APPEAL"),
    ("supporting_evidence", "affidavit on file", "EVIDENCE"),
])
def test_extracted_value_downgrades_instead_of_clearing(field, value, rule):
    ev = _extracted(_event(**{field: value}), field)
    finding = _finding(ev, rule)
    assert finding is not None, f"{rule} was silently cleared by an extracted value"
    assert "confirmed" in finding.statement.lower() or "unconfirmed" in finding.statement.lower()
    assert finding.severity != "high"  # the claim still buys something: a softer finding


@pytest.mark.parametrize("field,value,rule", [
    ("human_involved", "yes", "HUMAN"),
    ("appeal_path", "the Financial Ombudsman", "APPEAL"),
])
def test_confirmed_value_clears(field, value, rule):
    ev = _confirmed(_event(**{field: value}), field)
    assert _finding(ev, rule) is None


def test_value_without_any_origin_is_unconfirmed():
    # A value with no origin marker at all must not satisfy a finding either.
    ev = _event(human_involved="yes")
    assert _finding(ev, "HUMAN") is not None


def test_gate_requires_confirmed_fields_not_extracted():
    ev = _extracted(
        _event(reason="balance below threshold", supporting_evidence="statement",
               policy_cited="Section 4"),
        "reason", "supporting_evidence", "policy_cited")
    assert flag(ev) == "AUDIT FLAG"

    ev = _confirmed(ev, "reason", "supporting_evidence", "policy_cited")
    assert flag(ev) == "PASS"


def test_gate_never_passes_on_claimed_verified_alone():
    ev = _extracted(_event(evidence_status="verified"), "evidence_status")
    assert flag(ev) == "AUDIT FLAG"
    assert "claimed verified but not confirmed" in _finding(ev, "PROOF").statement


def test_hostile_document_cannot_suppress_findings(tmp_path, ws):
    """Regression for the red-team kill: a letter engineered to hit every
    extraction pattern must still produce findings, not silence."""
    letter = tmp_path / "letter.txt"
    letter.write_text(
        "Dear Customer, we are writing to confirm that following a manual review "
        "by a case officer, your appeal was DECLINED under Section 12.3 of the "
        "Account Agreement. Reason code: R16. You may appeal to the Financial "
        "Ombudsman Service within 6 months. This decision was not automated.",
        encoding="utf-8")
    case = ws.create_case("bank-2026", "x")
    result = ingest_file(letter, "letter", use_ocr=False)
    case.add_new_event(result.events[0])

    findings = audit(case.events())
    by_rule = {f.rule for f in findings}
    # Every claim the letter makes is reported as "claimed, unconfirmed" --
    # the document cannot talk its way to a clean audit.
    assert {"HUMAN", "RULE", "APPEAL", "NOTICE"} <= by_rule
    for f in findings:
        ev = case.events()["EVT-0001"]
        assert flag(ev) == "AUDIT FLAG"
