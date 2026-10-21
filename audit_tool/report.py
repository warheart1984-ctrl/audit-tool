"""Render a case file as Markdown (for people) or JSON (for other tools)."""

from __future__ import annotations

import json
from collections import Counter

from .ledger import now_iso
from .models import Event
from .rules import Finding, audit, flag, is_adverse
from .store import Case

LEDGER_FIELDS = [
    ("Source", "source"), ("Type", "source_type"), ("Timestamp", "timestamp"),
    ("Sender", "sender"), ("Recipient", "recipient"), ("Request", "request"),
    ("Decision", "decision"), ("Code", "status_code"), ("Reason", "reason"),
    ("Policy cited", "policy_cited"), ("Legal basis", "legal_basis"),
    ("Automated", "automated"), ("Human involved", "human_involved"),
    ("Notice provided", "notice_provided"), ("Appeal path", "appeal_path"),
    ("Reproducible", "reproducible"), ("Supporting evidence", "supporting_evidence"),
    ("Outcome", "outcome"), ("Evidence status", "evidence_status"), ("Notes", "notes"),
]


def _cell(text: str) -> str:
    return (text or "—").replace("|", "\\|").replace("\n", " ")


def _value(ev: Event, name: str) -> str:
    value = getattr(ev, name)
    if not value or value == "unknown":
        return value or ""
    return f"{value}  *(extracted, unconfirmed)*" if ev.origin.get(name) == "extracted" else value


def render_markdown(case: Case) -> str:
    info = case.info()
    events = case.events()
    findings = audit(events)
    problems = case.verify()
    ordered = sorted(events.values(), key=lambda e: (e.timestamp or "~", e.id))
    by_event: dict[str, list[Finding]] = {}
    for f in findings:
        by_event.setdefault(f.event_id, []).append(f)

    lines = [f"# Case file: {info.get('title', case.id)}", ""]
    lines += [f"- **Case ID:** {case.id}"]
    if info.get("subject"):
        lines.append(f"- **Subject:** {info['subject']}")
    if info.get("institution"):
        lines.append(f"- **Institution:** {info['institution']}")
    lines += [f"- **Generated:** {now_iso()}",
              f"- **Ledger integrity:** {'VERIFIED' if not problems else 'FAILED, see Integrity section'}", ""]

    sev = Counter(f.severity for f in findings)
    adverse = [e for e in ordered if is_adverse(e)]
    flagged = [e for e in adverse if flag(e) == "AUDIT FLAG"]
    lines += ["## Summary", "",
              f"{len(events)} events recorded, {len(adverse)} adverse decisions, "
              f"{len(flagged)} flagged for audit. Findings: {sev['high']} high, "
              f"{sev['medium']} medium, {sev['info']} informational.", ""]

    lines += ["## Timeline", "", "| ID | Timestamp | Type | Decision | Code | Gate |", "|---|---|---|---|---|---|"]
    for ev in ordered:
        lines.append(f"| {ev.id} | {_cell(ev.timestamp)} | {ev.source_type} | {_cell(ev.decision)} "
                     f"| {_cell(ev.status_code)} | {flag(ev)} |")
    lines.append("")

    lines += ["## Audit findings", ""]
    if not flagged and not findings:
        lines += ["No adverse decisions recorded.", ""]
    for ev in adverse:
        evf = by_event.get(ev.id, [])
        lines += [f"### Decision {ev.id}: {ev.decision}", ""]
        # Factual statement block: what the record shows, one line per gap.
        lines.append("```text")
        lines.append(f"Decision {ev.id} ({ev.decision}{', ' + ev.status_code if ev.status_code else ''})"
                     f"{' on ' + ev.timestamp if ev.timestamp else ''}.")
        for f in evf:
            if f.severity != "info" or f.rule == "AUTO":
                lines.append(f.statement)
        lines.append("```")
        lines += ["", "| Finding | Question | Severity | Statement |", "|---|---|---|---|"]
        for f in evf:
            lines.append(f"| {f.id} | {f.question} | {f.severity} | {_cell(f.statement)} |")
        lines.append("")

    lines += ["## Evidence ledger", ""]
    for ev in ordered:
        lines += [f"### {ev.id}", "", "```text", f"ID: {ev.id}"]
        for label, name in LEDGER_FIELDS:
            val = _value(ev, name)
            if val:
                lines.append(f"{label}: {val}")
        lines.append("```")
        for art in ev.artifacts:
            lines.append(f"- Artifact `{art['original_name']}` → `{art['stored_path']}`, "
                         f"{art['size']} bytes, SHA-256 `{art['sha256']}`")
        lines.append("")

    lines += ["## Integrity", ""]
    if problems:
        lines += [f"- {p}" for p in problems]
    else:
        lines.append(f"All {len(case.ledger.entries())} ledger entries chain correctly and every "
                     "evidence file matches its recorded SHA-256 hash.")
    lines += ["", "## Method and limitations", "",
              "- Each finding describes what is **absent from the collected record**. It does not "
              "claim that something did not happen inside the institution.",
              "- Fields marked *(extracted, unconfirmed)* were pulled out automatically and have not "
              "yet been checked by a person.",
              "- Copies of the evidence are stored byte for byte and identified by SHA-256. The ledger "
              "is append-only and hash-chained, so any later change to a recorded entry can be detected.",
              "- This report is not legal advice.", ""]
    return "\n".join(lines)


def render_json(case: Case) -> str:
    events = case.events()
    return json.dumps({
        "case": case.info(),
        "generated": now_iso(),
        "integrity_problems": case.verify(),
        "events": [dict(e.to_dict(), gate=flag(e)) for e in events.values()],
        "findings": [f.__dict__ for f in audit(events)],
    }, indent=2, ensure_ascii=False)
