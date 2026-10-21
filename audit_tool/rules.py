"""Audit checks: the questions an auditor asks of every adverse automated decision.

Findings describe what the *record* shows, not what happened inside the institution.
"No human review record" means none has been provided or collected, which is the
claim the evidence can actually support.

Extracted values come from documents the audited party wrote. If they could clear
a finding, an institution could write letters that pass the audit ("manually
reviewed by a case officer", "you may appeal"). So only a value a person has
confirmed (`audit edit`) clears a finding; an extracted one turns the finding into
a "claimed, unconfirmed" one instead.
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


def confirmed(ev: Event, name: str) -> bool:
    return bool(getattr(ev, name)) and ev.origin.get(name) == "confirmed"


def _quote(text: str, limit: int = 80) -> str:
    text = " ".join(text.split())
    return f'"{text[:limit]}…"' if len(text) > limit else f'"{text}"'


def _check(ev: Event) -> list[tuple[str, str, str, str]]:
    """Return (rule, question, severity, statement) for each gap in the record."""
    out = []

    q = "Was the decision automatic?"
    if ev.automated == "yes":
        out.append(("AUTO", q, "info", "The decision was made automatically." if confirmed(ev, "automated")
                    else "The document indicates the decision was made automatically (unconfirmed)."))
    elif ev.automated == "unknown":
        out.append(("AUTO", q, "medium",
                    "The record does not show whether the decision was automated or made by a person."))

    q = "Was a human involved?"
    if ev.human_involved == "yes" and not confirmed(ev, "human_involved"):
        out.append(("HUMAN", q, "medium",
                    "The document claims a person reviewed the decision; no confirmed review record exists."))
    elif ev.human_involved != "yes":
        out.append(("HUMAN", q, "high" if ev.automated == "yes" else "medium",
                    "No human review record has been provided."))

    q = "What rule triggered it?"
    if ev.policy_cited and not confirmed(ev, "policy_cited"):
        out.append(("RULE", q, "medium",
                    f"The document cites {_quote(ev.policy_cited)}; the rule and its text are not confirmed."))
    elif not (ev.policy_cited or ev.status_code):
        out.append(("RULE", q, "high", "No rule, policy or code was cited for the decision."))
    elif not ev.policy_cited:
        out.append(("RULE", q, "medium",
                    f"Only a system code ({ev.status_code}) was given; no written policy was cited."))

    q = "What evidence supported the rule?"
    if ev.supporting_evidence and not confirmed(ev, "supporting_evidence"):
        out.append(("EVIDENCE", q, "medium",
                    "Supporting evidence is claimed but has not been confirmed."))
    elif not ev.supporting_evidence:
        out.append(("EVIDENCE", q, "high", "No supporting evidence was provided for the decision."))

    q = "Was notice provided?"
    if ev.notice_provided == "yes" and not confirmed(ev, "notice_provided"):
        out.append(("NOTICE", q, "info",
                    "Notice is inferred from the document itself (unconfirmed)."))
    elif ev.notice_provided == "no":
        out.append(("NOTICE", q, "high", "No notice of the decision was provided."))
    elif ev.notice_provided == "unknown":
        out.append(("NOTICE", q, "medium",
                    "The record does not show that notice of the decision was provided."))

    q = "Was an appeal path disclosed?"
    if ev.appeal_path and not confirmed(ev, "appeal_path"):
        out.append(("APPEAL", q, "medium",
                    f"The document mentions {_quote(ev.appeal_path)}; it is not confirmed to be a usable appeal path."))
    elif not ev.appeal_path:
        out.append(("APPEAL", q, "high", "No appeal path was disclosed."))

    if ev.reproducible == "no" or (ev.reproducible == "unknown" and not ev.reason):
        out.append(("REPRO", "Is the decision reproducible?", "high",
                    "The decision cannot be explained or reproduced from the reason given."
                    if ev.reason else "No reason was given, so the decision cannot be explained or reproduced."))

    if not confirmed(ev, "legal_basis"):
        out.append(("LAW", "Does policy or law permit the action?", "info",
                    "No legal or contractual basis has been identified yet (needs review)."))

    if not (ev.evidence_status == "verified" and confirmed(ev, "evidence_status")):
        status = ev.evidence_status if ev.evidence_status != "verified" else "claimed verified but not confirmed"
        out.append(("PROOF", "Is the event itself documented?", "medium",
                    f"Our own evidence that this event occurred is {status}."))
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
    """The pass/flag gate: is there confirmed evidence behind the decision?"""
    if not is_adverse(ev):
        return "N/A"
    has_rule = confirmed(ev, "policy_cited") or confirmed(ev, "status_code")
    return "PASS" if confirmed(ev, "reason") and confirmed(ev, "supporting_evidence") and has_rule else "AUDIT FLAG"
