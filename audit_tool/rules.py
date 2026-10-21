"""Audit checks: the questions an auditor asks of every adverse automated decision.

Findings describe what the *record* shows, not what happened inside the institution.
"No human review record" means none has been provided or collected, which is the
claim the evidence can actually support.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Event

FAVOURABLE = {"approved", "accepted", "delivered", "completed", "posted"}


@dataclass
class Finding:
    id: str
    event_id: str
    rule: str
    question: str
    severity: str  # high | medium | info
    statement: str


def is_adverse(ev: Event) -> bool:
    return bool(ev.decision) and ev.decision.strip().lower() not in FAVOURABLE


def _check(ev: Event) -> list[tuple[str, str, str, str]]:
    """Return (rule, question, severity, statement) for each gap in the record."""
    out = []

    if ev.automated == "yes":
        out.append(("AUTO", "Was the decision automatic?", "info",
                    "The decision was made automatically."))
    elif ev.automated == "unknown":
        out.append(("AUTO", "Was the decision automatic?", "medium",
                    "The record does not show whether the decision was automated or made by a person."))

    if ev.human_involved != "yes":
        sev = "high" if ev.automated == "yes" else "medium"
        out.append(("HUMAN", "Was a human involved?", sev,
                    "No human review record has been provided."))

    if not (ev.policy_cited or ev.status_code):
        out.append(("RULE", "What rule triggered it?", "high",
                    "No rule, policy or code was cited for the decision."))
    elif not ev.policy_cited:
        out.append(("RULE", "What rule triggered it?", "medium",
                    f"Only a system code ({ev.status_code}) was given; no written policy was cited."))

    if not ev.supporting_evidence:
        out.append(("EVIDENCE", "What evidence supported the rule?", "high",
                    "No supporting evidence was provided for the decision."))

    if ev.notice_provided == "no":
        out.append(("NOTICE", "Was notice provided?", "high", "No notice of the decision was provided."))
    elif ev.notice_provided == "unknown":
        out.append(("NOTICE", "Was notice provided?", "medium",
                    "The record does not show that notice of the decision was provided."))

    if not ev.appeal_path:
        out.append(("APPEAL", "Was an appeal path disclosed?", "high", "No appeal path was disclosed."))

    if ev.reproducible == "no" or (ev.reproducible == "unknown" and not ev.reason):
        out.append(("REPRO", "Is the decision reproducible?", "high",
                    "The decision cannot be explained or reproduced from the reason given."
                    if ev.reason else "No reason was given, so the decision cannot be explained or reproduced."))

    if not ev.legal_basis:
        out.append(("LAW", "Does policy or law permit the action?", "info",
                    "No legal or contractual basis has been identified yet (needs review)."))

    if ev.evidence_status != "verified":
        out.append(("PROOF", "Is the event itself documented?", "medium",
                    f"Our own evidence that this event occurred is {ev.evidence_status}."))
    return out


def audit(events: dict[str, Event]) -> list[Finding]:
    findings = []
    for ev in sorted(events.values(), key=lambda e: (e.timestamp or "~", e.id)):
        if not is_adverse(ev):
            continue
        for rule, question, severity, statement in _check(ev):
            findings.append(Finding(f"AF-{len(findings) + 1:04d}", ev.id, rule, question, severity, statement))
    return findings


def flag(ev: Event) -> str:
    """The pass/flag gate: is there evidence behind the decision?"""
    if not is_adverse(ev):
        return "N/A"
    return "PASS" if ev.reason and ev.supporting_evidence and (ev.policy_cited or ev.status_code) else "AUDIT FLAG"
