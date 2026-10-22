"""Command line interface: `audit <command> ...` or `python -m audit_tool <command> ...`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .extract import extract_isolated
from .ingest import ingest_file
from .ledger import generate_keypair, key_id, load_private_key, load_public_key
from .models import EDITABLE, SOURCE_TYPES, validate_field
from .report import LEDGER_FIELDS, render_json, render_markdown
from .rules import audit, flag
from .secure import loose_permissions, restrict_file, restrict_tree
from .store import PUBLIC_KEY_FILE, Case, Workspace, sha256_file


def _outside_root(path: Path, root: Path) -> None:
    if path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"keep the key outside the cases folder ({root}); anyone who can write "
                         "the ledger could otherwise also read the key")


def print_head(case: Case) -> None:
    print(f"Ledger anchor: {case.ledger.anchor()}")
    print("  (Save this off this machine. `audit verify --expect <anchor>` later proves nothing up to it "
          "was rewritten; add --exact to prove nothing after it was added or removed.)")


def require_intact(case: Case, a) -> list[str]:
    """Read commands act on the replayed state, so they must not run on a ledger that fails verification."""
    problems = case.verify()
    if problems and not getattr(a, "unverified", False):
        print(f"INTEGRITY FAILED for case {case.id}; refusing to show results from a ledger that "
              "doesn't verify. Run `audit verify` for details, or pass --unverified to look anyway.")
        for p in problems[:10]:
            print(f"  - {p}")
        sys.exit(2)
    if problems:
        print(f"WARNING: case {case.id} FAILS integrity verification ({len(problems)} problem(s)); "
              "the results below may be forged.\n")
    return problems


def cmd_new(ws: Workspace, a) -> None:
    case = ws.create_case(a.case, a.title, a.subject, a.institution)
    print(f"Created case {case.id} at {case.dir} (owner-only access)")
    print_head(case)


def cmd_list(ws: Workspace, a) -> None:
    cases = ws.list_cases()
    if not cases:
        print(f"No cases under {ws.root}")
    for case in cases:
        if case.verify():
            print(f"{case.id:20} INTEGRITY FAILED (run `audit verify {case.id}`)")
            continue
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
        artifact = case.store_artifact(path)
        if artifact["sha256"] != digest:
            raise ValueError(f"{path} changed while it was being ingested; try again")
        if not result.events:
            # Still evidence: proof that this file was checked and what was (not) found.
            note = "No adverse decisions found."
            if result.warnings:
                note += " Ingest warnings: " + "; ".join(result.warnings)
            case.record_artifact(artifact, note)
            print(f"{path.name}: no adverse decisions found (kept on record)")
            continue
        linked = [artifact]
        if result.extracted and result.extracted.text.strip():
            linked.append(case.store_derived_text(artifact, result.extracted.text, result.extracted.method))
        for fields_ in result.events:
            ev = case.add_new_event(fields_, *linked)
            if a.source:
                # A person stated this, so it is recorded as a confirmation (an edit), not at creation.
                case.update_event(ev.id, {"source": a.source}, "--source given at ingest")
                ev.source = a.source
            via = f" [{result.extracted.method}]" if result.extracted and result.extracted.method else ""
            print(f"{ev.id}  {ev.source_type:11} {ev.decision or '(no decision found)':28} "
                  f"{ev.status_code}  ← {path.name}{via}")
    print_head(case)


def cmd_extract(ws: Workspace, a) -> None:
    ex = extract_isolated(Path(a.file))
    for warning in ex.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"# method: {ex.method or 'none'}"
          + (f", mean confidence {ex.confidence:.2f}" if ex.confidence is not None else ""))
    print(ex.text)


def cmd_add(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    changes = {}
    for pair in a.set or []:
        name, sep, value = pair.partition("=")
        if not sep:
            raise ValueError(f"Expected field=value, got '{pair}'")
        changes[name.strip()] = validate_field(name.strip(), value)
    with case.ledger.locked():
        ev = case.add_new_event({})
        # Facts typed by a person are confirmations, which only edits can record.
        if changes:
            case.update_event(ev.id, changes, "entered by hand with `audit add`")
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
    require_intact(case, a)
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
    require_intact(case, a)
    findings = audit(case.events())
    if not findings:
        print("No findings.")
    for f in findings:
        print(f"{f.id}  {f.event_id}  {f.severity:6}  {f.rule:8} {f.statement}")


def cmd_verify(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    key_note = None
    if case.ledger.verify_key is None and case.ledger.is_signed() and (case.dir / PUBLIC_KEY_FILE).exists():
        # Fall back to the public key shipped with the case; it is only as good as
        # the key id the owner saved elsewhere, so say which one it is.
        case = Case(case.dir, verify_key=load_public_key(case.dir / PUBLIC_KEY_FILE))
        key_note = (f"Note: checked signatures with the public key stored in the case folder (key id "
                    f"{case.ledger.kid}). Compare that id with the one the owner gave you; pass "
                    "--public-key to use a copy you trust instead.")
    problems = case.verify(expect_head=a.expect, exact=a.exact)
    if problems:
        print("INTEGRITY FAILED")
        for p in problems:
            print(f"  - {p}")
        sys.exit(2)
    print("OK: ledger chain intact, every evidence file matches its hash, and the "
          "evidence folder holds only recorded files.")
    if a.expect:
        print(f"OK: anchor {a.expect} is in the ledger at its position; history up to it is unchanged.")
        after = case.entries_after(a.expect)
        if a.exact:
            print("OK: the anchor is the newest entry; nothing was added or removed after it.")
        elif after:
            print(f"Note: {after} entr{'y was' if after == 1 else 'ies were'} added after that anchor and "
                  "are NOT covered by it. Review them, then save the new anchor.")
        else:
            print("Note: entries deleted after an anchor can't be seen without --exact.")
    else:
        print("Note: without --expect, this can't rule out the whole ledger having been replaced.")
    if case.ledger.verify_key is not None:
        prefix = case.ledger.unsigned_prefix()
        print(f"OK: every entry from #{prefix + 1} on is signed by key {case.ledger.kid}."
              + (f" Entries 1-{prefix} predate signing." if prefix else ""))
        if key_note:
            print(key_note)
    elif case.ledger.is_signed():
        print("Note: entries are signed; pass --public-key (or --key-file) to check the signatures.")
    else:
        print("Note: entries are unsigned, so this can't show who wrote them (see `audit keygen`).")
    if loose := loose_permissions(case.dir):
        print(f"Warning: {len(loose)} path(s) are readable by other accounts; run `audit secure {case.id}`.")
    print(f"Ledger anchor: {case.ledger.anchor()}")


def cmd_head(ws: Workspace, a) -> None:
    print(ws.open_case(a.case).ledger.anchor())


def cmd_secure(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    restrict_tree(case.dir)
    print(f"Restricted {case.dir} to the current user" + (" and SYSTEM." if sys.platform == "win32" else "."))


def cmd_keygen(ws: Workspace, a) -> None:
    path = Path(a.path)
    pub = path.with_name(path.name + ".pub")
    _outside_root(path, ws.root)
    for p in (path, pub):
        if p.exists():
            raise FileExistsError(f"{p} already exists; not overwriting a key")
    priv_pem, pub_pem = generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(priv_pem)
    restrict_file(path)
    pub.write_bytes(pub_pem)
    kid = key_id(load_public_key(pub))
    print(f"Wrote private key to {path} and public key to {pub} (key id {kid}).")
    print("Keep the private key off shared drives and out of git: whoever holds it can sign as you.")
    print(f"Give the public key (or just the key id {kid}) to anyone who should check your signatures;")
    print("they can verify with it but cannot forge entries.")


def cmd_report(ws: Workspace, a) -> None:
    case = ws.open_case(a.case)
    problems = case.verify()
    text = render_json(case) if a.format == "json" else render_markdown(case)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"Wrote {a.out}")
    else:
        print(text)
    if problems:
        print(f"INTEGRITY FAILED for case {case.id}: the report is marked as unreliable.", file=sys.stderr)
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit", description="Build evidence-based case files for automated decisions.")
    p.add_argument("--root", default="cases", help="workspace folder holding cases (default: ./cases)")
    p.add_argument("--key-file", default=os.environ.get("AUDIT_KEY_FILE"),
                   help="Ed25519 private key (outside the cases folder); signs new entries and checks "
                        "signatures. Default: $AUDIT_KEY_FILE")
    p.add_argument("--public-key", default=os.environ.get("AUDIT_PUBLIC_KEY"),
                   help="Ed25519 public key to check signatures with (no signing). Default: $AUDIT_PUBLIC_KEY")
    p.add_argument("--actor", default=os.environ.get("AUDIT_ACTOR"),
                   help="name recorded as the author of new entries. Default: $AUDIT_ACTOR")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("keygen", help="create an Ed25519 signing key pair (PATH and PATH.pub)")
    s.add_argument("path")
    s.set_defaults(func=cmd_keygen)

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
    s.add_argument("--unverified", action="store_true", help="show even if the ledger fails verification")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("check", help="run audit checks")
    s.add_argument("case")
    s.add_argument("--unverified", action="store_true", help="check even if the ledger fails verification")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("verify", help="verify ledger chain, signatures and evidence hashes")
    s.add_argument("case")
    s.add_argument("--expect", metavar="ANCHOR",
                   help="an anchor (<seq>:<hash>) saved earlier; fails if it is no longer at that position")
    s.add_argument("--exact", action="store_true",
                   help="with --expect: also fail if any entry was added or removed after the anchor")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("head", help="print the ledger anchor (<seq>:<hash>) to save off this machine")
    s.add_argument("case")
    s.set_defaults(func=cmd_head)

    s = sub.add_parser("secure", help="restrict an existing case folder to the current user")
    s.add_argument("case")
    s.set_defaults(func=cmd_secure)

    s = sub.add_parser("report", help="render the case file (exit code 2 if integrity fails)")
    s.add_argument("case")
    s.add_argument("--format", choices=("md", "json"), default="md")
    s.add_argument("--out")
    s.set_defaults(func=cmd_report)
    return p


def _keys(args, root: Path):
    signer = verify_key = None
    if args.key_file and args.command != "keygen":
        key_path = Path(args.key_file)
        _outside_root(key_path, root)
        signer = load_private_key(key_path)
    if args.public_key:
        verify_key = load_public_key(Path(args.public_key))
        if signer is not None and key_id(verify_key) != key_id(signer.public_key()):
            raise ValueError("--public-key does not belong to --key-file")
    return signer, verify_key


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    # Windows consoles default to a legacy code page that can't print evidence text.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        root = Path(args.root)
        signer, verify_key = _keys(args, root)
        args.func(Workspace(root, signer=signer, verify_key=verify_key, actor=args.actor), args)
    except (ValueError, KeyError, FileNotFoundError, FileExistsError, TimeoutError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
