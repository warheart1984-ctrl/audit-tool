"""Command line interface: `audit <command> ...` or `python -m audit_tool <command> ...`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .extract import extract
from .ingest import ingest_file
from .models import EDITABLE, SOURCE_TYPES, Event, validate_field
from .report import LEDGER_FIELDS, render_json, render_markdown
from .rules import audit, flag
from .store import Case, Workspace, sha256_file


def print_head(case: Case) -> None:
    print(f"Ledger head: {case.ledger.head()}")
    print("  (Save this hash off this machine. `audit verify --expect <hash>` later proves "
          "nothing before it was rewritten.)")


def cmd_new(ws: Workspace, a) -> None:
    case = ws.create_case(a.case, a.title, a.subject, a.institution)
    print(f"Created case {case.id} at {case.dir}")
    print_head(case)


def cmd_list(ws: Workspace, a) -> None:
    cases = ws.list_cases()
    if not cases:
        print(f"No cases under {ws.root}")
    for case in cases:
        events = case.events()
        flagged = sum(1 for e in events.values() if flag(e) == "AUDIT FLAG")
        print(f"{case.id:20} {len(events):3} events  {flagged:3} flagged  {case.info().get('title', '')}")


def cmd_ingest(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    for raw in a.files:
        path = Path(raw)
        if not path.is_file():
            print(f"skip: {path} is not a file", file=sys.stderr)
            continue
        digest = sha256_file(path)
        result = ingest_file(path, a.type, use_ocr=not a.no_ocr)
        for warning in result.warnings:
            print(f"warning: {path.name}: {warning}", file=sys.stderr)
        if not result.events:
            print(f"{path.name}: no adverse decisions found (not stored)")
            continue
        # Store only once there is an event to link it to, so the evidence folder
        # never holds files the ledger doesn't list.
        artifact = case.store_artifact(path)
        if artifact["sha256"] != digest:
            raise ValueError(f"{path} changed while it was being ingested; try again")
        linked = [artifact]
        if result.extracted and result.extracted.text.strip():
            linked.append(case.store_derived_text(artifact, result.extracted.text, result.extracted.method))
        for fields_ in result.events:
            ev = Event.from_dict(dict(fields_, id=case.next_event_id()))
            if a.source:
                ev.source = a.source
                ev.origin["source"] = "confirmed"
            case.add_event(ev, *linked)
            via = f" [{result.extracted.method}]" if result.extracted and result.extracted.method else ""
            print(f"{ev.id}  {ev.source_type:11} {ev.decision or '(no decision found)':28} "
                  f"{ev.status_code}  ← {path.name}{via}")
    print_head(case)


def cmd_extract(ws: Workspace, a) -> None:
    ex = extract(Path(a.file))
    for warning in ex.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"# method: {ex.method or 'none'}"
          + (f", mean confidence {ex.confidence:.2f}" if ex.confidence is not None else ""))
    print(ex.text)


def cmd_add(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    ev = Event(id=case.next_event_id())
    for pair in a.set or []:
        name, _, value = pair.partition("=")
        setattr(ev, name.strip(), validate_field(name.strip(), value))
        ev.origin[name.strip()] = "confirmed"
    case.add_event(ev)
    print(f"Added {ev.id}")
    print_head(case)


def cmd_edit(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    changes = {}
    for pair in a.set:
        name, sep, value = pair.partition("=")
        if not sep:
            raise ValueError(f"Expected field=value, got '{pair}'")
        changes[name.strip()] = validate_field(name.strip(), value)
    case.update_event(a.event, changes, a.reason)
    print(f"Updated {a.event}: {', '.join(changes)}")
    print_head(case)


def cmd_attach(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    art = case.link_artifact(a.event, Path(a.file))
    print(f"Attached {art['original_name']} to {a.event} (sha256 {art['sha256'][:16]}…)")
    print_head(case)


def cmd_show(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    events = case.events()
    if a.event not in events:
        raise KeyError(f"No event {a.event}")
    ev = events[a.event]
    print(f"ID: {ev.id}   [{flag(ev)}]")
    for label, name in LEDGER_FIELDS:
        value = getattr(ev, name)
        tag = f"  ({ev.origin[name]})" if ev.origin.get(name) else ""
        print(f"  {label + ':':21} {value or '—'}{tag}")
    for art in ev.artifacts:
        print(f"  Artifact: {art['stored_path']}  sha256 {art['sha256']}")


def cmd_check(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    findings = audit(case.events())
    if not findings:
        print("No findings.")
    for f in findings:
        print(f"{f.id}  {f.event_id}  {f.severity:6}  {f.rule:8} {f.statement}")


def cmd_verify(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    problems = case.verify(expect_head=a.expect)
    if problems:
        print("INTEGRITY FAILED")
        for p in problems:
            print(f"  - {p}")
        sys.exit(2)
    print("OK: ledger chain intact, every evidence file matches its hash, and the "
          "evidence folder holds only recorded files.")
    if a.expect:
        print(f"OK: anchored head {a.expect} is in the ledger; history up to it is unchanged.")
    else:
        print("Note: without --expect, this can't rule out the whole ledger having been replaced.")
    print(f"Ledger head: {case.ledger.head()}")


def cmd_head(ws: Workspace, a) -> None:
    print(ws.open_case(a.case).ledger.head())


def cmd_report(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    text = render_json(case) if a.format == "json" else render_markdown(case)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"Wrote {a.out}")
    else:
        print(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit", description="Build evidence-based case files for automated decisions.")
    p.add_argument("--root", default="cases", help="workspace folder holding cases (default: ./cases)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("new", help="create a case")
    s.add_argument("case")
    s.add_argument("--title", required=True)
    s.add_argument("--subject", default="", help="whose case this is")
    s.add_argument("--institution", default="", help="bank or organisation involved")
    s.set_defaults(func=cmd_new)

    sub.add_parser("list", help="list cases").set_defaults(func=cmd_list)

    s = sub.add_parser("ingest", help="ingest emails, letters, transcripts, chats, CSVs, screenshots")
    s.add_argument("case")
    s.add_argument("files", nargs="+")
    s.add_argument("--type", choices=SOURCE_TYPES, help="override detected artifact type")
    s.add_argument("--source", help="system/institution that produced it, e.g. 'Microsoft 365'")
    s.add_argument("--no-ocr", action="store_true", help="don't OCR screenshots or read PDF text")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("extract", help="preview the text OCR/PDF extraction gets from a file")
    s.add_argument("file")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("add", help="add an event by hand")
    s.add_argument("case")
    s.add_argument("--set", action="append", metavar="FIELD=VALUE")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("edit", help="confirm or correct fields of an event (recorded in the ledger)")
    s.add_argument("case")
    s.add_argument("event")
    s.add_argument("--set", action="append", required=True, metavar="FIELD=VALUE",
                   help=f"fields: {', '.join(EDITABLE)}")
    s.add_argument("--reason", default="manual review", help="why the change was made")
    s.set_defaults(func=cmd_edit)

    s = sub.add_parser("attach", help="attach another evidence file to an event")
    s.add_argument("case")
    s.add_argument("event")
    s.add_argument("file")
    s.set_defaults(func=cmd_attach)

    s = sub.add_parser("show", help="show one event")
    s.add_argument("case")
    s.add_argument("event")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("check", help="run audit checks")
    s.add_argument("case")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("verify", help="verify ledger chain and evidence hashes")
    s.add_argument("case")
    s.add_argument("--expect", metavar="HASH", help="a head hash saved earlier; fails if it is no longer in the ledger")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("head", help="print the ledger head hash, to save somewhere off this machine")
    s.add_argument("case")
    s.set_defaults(func=cmd_head)

    s = sub.add_parser("report", help="render the case file")
    s.add_argument("case")
    s.add_argument("--format", choices=("md", "json"), default="md")
    s.add_argument("--out")
    s.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    # Windows consoles default to a legacy code page that can't print evidence text.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        args.func(Workspace(Path(args.root)), args)
    except (ValueError, KeyError, FileNotFoundError, FileExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
