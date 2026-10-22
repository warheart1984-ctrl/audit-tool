#!/usr/bin/env python3
"""Build a ledger corpus with the audit tool CLI and compare verifiers.

Real cases come from ``python -m audit_tool``. Tampered copies are made
from those files. The private signing key stays in a temporary directory
and is wiped before this script exits. It is never printed.

Expectations in this file were fixed from docs/LEDGER_FORMAT.md before
the comparison is run:

* hash and signatures are over the canonical object, so reordered keys
  and ``\\u`` escapes that decode to the same text still verify
* ``--expect`` without ``--exact`` accepts entries after the anchor
* ``--exact``, a missing anchored entry, and a changed anchored hash fail
* a ``kid`` without a ``sig``, a bad ``sig``, or a ``kid`` that is not the
  public key's id fails
* a lone surrogate cannot be canonical UTF-8
* a fully recomputed chain verifies; the old anchor does not
* an unsigned ledger is valid ledger format even if a public key is supplied
  (the README's verify command is stricter; that row is expected to disagree)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_ledger import GENESIS_PREV, entry_hash

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
# Not named "cases/": the repo gitignore ignores every directory with that name.
CASES = CORPUS / "ledgers"
PUB_NAME = "signing.key.pub"
FIELD_ORDER = ("seq", "ts", "kind", "payload", "prev", "actor", "kid", "hash", "sig")


@dataclass
class Run:
    case: str
    name: str
    spec_ok: bool
    expect: str | None = None
    exact: bool = False
    use_key: bool = False
    note: str = ""


@dataclass
class Outcome:
    status: str
    code: int | None
    summary: str
    codes: list[str] = field(default_factory=list)


def main() -> int:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CASES.mkdir(parents=True)
    env = os.environ.copy()
    for name in ("AUDIT_KEY_FILE", "AUDIT_PUBLIC_KEY", "AUDIT_ACTOR"):
        env.pop(name, None)

    with tempfile.TemporaryDirectory(prefix="ledger-corpus-") as tmp_name:
        tmp = Path(tmp_name)
        priv = tmp / "signing.key"
        pub = tmp / PUB_NAME
        work = tmp / "cases"
        work.mkdir()
        inputs = _write_inputs(tmp / "inputs")
        _run(
            [
                sys.executable,
                "-m",
                "audit_tool",
                "--root",
                str(work),
                "keygen",
                str(priv),
            ],
            env,
        )
        _build_real_cases(work, inputs, priv, env)
        pub_bytes = pub.read_bytes()
        (CORPUS / PUB_NAME).write_bytes(pub_bytes)
        for case_id in ("01-unsigned-unicode", "02-signed-unicode", "03-second-case"):
            shutil.copytree(work / case_id, CASES / case_id)
        anchors = {
            "01-unsigned-unicode": _tip(CASES / "01-unsigned-unicode"),
            "02-signed-unicode": _tip(CASES / "02-signed-unicode"),
            "03-second-case": _tip(CASES / "03-second-case"),
        }
        _confirm_head(work, anchors, env)
        _make_tampers(CASES, priv)
        runs = _runs(anchors)
        private_key = load_pem_private_key(priv.read_bytes(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise SystemExit("keygen did not write an Ed25519 private key")
        _apply_wrong_kid(CASES / "09-wrong-kid", private_key)
        # Drop the only copy of the private key before comparison output.
        _wipe(priv)
        _wipe(tmp / "signing.key")

    _chmod_public(CORPUS)
    results = [_compare(run, env) for run in runs]
    (CORPUS / "compare.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    disagree = [row for row in results if not row["agree"]]
    print(f"runs={len(results)} disagreements={len(disagree)}")
    for row in results:
        mark = "AGREE" if row["agree"] else "DIFF"
        print(
            f"{mark} {row['case']} {row['name']}: "
            f"spec={'pass' if row['spec_ok'] else 'fail'} "
            f"tool={row['tool']['status']} clean={row['clean']['status']}"
        )
    return 0


def _write_inputs(path: Path) -> dict[str, Path]:
    path.mkdir()
    letter = path / "letter.txt"
    letter.write_text(
        "Example Bank\n10 October 2026\n\n"
        "Decision: Declined\n"
        "Reason: Insufficient funds on the account.\n"
        "Policy: Section 12.3 of the account terms.\n"
        "Date: 2026-10-10\n"
        "This decision was made by an automated system.\n"
        "No appeal path is disclosed in this letter.\n",
        encoding="utf-8",
    )
    notes = path / "notes.txt"
    notes.write_text(
        "Call transcript\n"
        "Agent: The payment was held.\n"
        "Customer: I was not told about an appeal.\n"
        "Decision: Held\n"
        "Reason: Review pending\n",
        encoding="utf-8",
    )
    csv_path = path / "statement.csv"
    csv_path.write_text(
        "date,description,amount,status\n"
        "2026-10-01,Payroll,1000.00,posted\n"
        "2026-10-02,Card payment,-42.10,declined\n"
        "2026-10-03,Transfer,-15.00,reversed\n",
        encoding="utf-8",
    )
    return {"letter": letter, "notes": notes, "csv": csv_path}


def _build_real_cases(
    work: Path, inputs: dict[str, Path], priv: Path, env: dict[str, str]
) -> None:
    root = ["--root", str(work)]
    _audit(
        [*root, "new", "01-unsigned-unicode", "--title", "Résumé — test",
         "--subject", "Alex Example", "--institution", "Example Bank"],
        env,
    )
    _audit(
        [*root, "ingest", "01-unsigned-unicode", str(inputs["letter"]),
         "--source", "Example Bank"],
        env,
    )
    _audit(
        [*root, "ingest", "01-unsigned-unicode", str(inputs["notes"]),
         "--type", "transcript", "--source", "Call"],
        env,
    )
    _audit(
        [*root, "ingest", "01-unsigned-unicode", str(inputs["csv"]),
         "--source", "Example Bank"],
        env,
    )
    _audit(
        [*root, "new", "02-signed-unicode", "--title", "Décision — café",
         "--subject", "René", "--institution", "Banque Exemple"],
        env,
    )
    _audit(
        ["--key-file", str(priv), "--actor", "alex", *root,
         "ingest", "02-signed-unicode", str(inputs["letter"]),
         "--source", "Banque Exemple"],
        env,
    )
    _audit(
        ["--key-file", str(priv), "--actor", "alex", *root,
         "add", "02-signed-unicode",
         "--set", "decision=Declined",
         "--set", "reason=manual note — déjà vu",
         "--set", "automated=yes"],
        env,
    )
    _audit(
        [*root, "new", "03-second-case", "--title", "Second case",
         "--institution", "Other"],
        env,
    )
    _audit(
        [*root, "ingest", "03-second-case", str(inputs["csv"]),
         "--source", "Other"],
        env,
    )


def _make_tampers(cases: Path, priv: Path) -> None:
    del priv  # wrong-kid signing happens after this, once the copy exists
    _copy("01-unsigned-unicode", "04-edited-field")
    _edit_field(cases / "04-edited-field")
    _copy("01-unsigned-unicode", "05-swapped-middle")
    _swap_middle(cases / "05-swapped-middle")
    _copy("01-unsigned-unicode", "06-truncated-tail")
    _truncate_tail(cases / "06-truncated-tail")
    _copy("01-unsigned-unicode", "07-append-after-anchor")
    _append_entry(cases / "07-append-after-anchor")
    _copy("02-signed-unicode", "08-stripped-earliest-sig")
    _strip_earliest_sig(cases / "08-stripped-earliest-sig")
    _copy("02-signed-unicode", "09-wrong-kid")
    _copy("02-signed-unicode", "10-reordered-keys")
    _reorder_keys(cases / "10-reordered-keys")
    _copy("01-unsigned-unicode", "11-u-escaped")
    _escape_unicode(cases / "11-u-escaped")
    _copy("01-unsigned-unicode", "12-lone-surrogate")
    _inject_surrogate(cases / "12-lone-surrogate")
    _copy("02-signed-unicode", "13-nonascii-sig")
    _nonascii_sig(cases / "13-nonascii-sig")
    _copy("01-unsigned-unicode", "14-replaced-genesis")
    _replace_genesis(cases / "14-replaced-genesis")
    _copy("01-unsigned-unicode", "15-unsigned-with-key")


def _runs(anchors: dict[str, str]) -> list[Run]:
    unsigned_tip = anchors["01-unsigned-unicode"]
    signed_tip = anchors["02-signed-unicode"]
    return [
        Run("01-unsigned-unicode", "plain", True, note="real unsigned unicode ledger"),
        Run("02-signed-unicode", "plain", True, use_key=True, note="real signed unicode ledger"),
        Run(
            "02-signed-unicode",
            "exact-anchor",
            True,
            expect=signed_tip,
            exact=True,
            use_key=True,
            note="anchor is the current tip",
        ),
        Run("03-second-case", "plain", True, note="second real unsigned case"),
        Run("04-edited-field", "plain", False, note="title edited, hash left unchanged"),
        Run(
            "05-swapped-middle",
            "plain",
            False,
            note="payloads of seq 5 and 6 swapped; only those two hashes recomputed",
        ),
        Run(
            "06-truncated-tail",
            "plain",
            True,
            note="prefix chain is still valid",
        ),
        Run(
            "06-truncated-tail",
            "expect-old-tip",
            False,
            expect=unsigned_tip,
            note="old tip seq is gone",
        ),
        Run("07-append-after-anchor", "plain", True, note="extended chain is valid"),
        Run(
            "07-append-after-anchor",
            "expect",
            True,
            expect=unsigned_tip,
            note="history up to the anchor is unchanged; later entry is only a warning",
        ),
        Run(
            "07-append-after-anchor",
            "exact",
            False,
            expect=unsigned_tip,
            exact=True,
            note="--exact rejects the appended entry",
        ),
        Run(
            "08-stripped-earliest-sig",
            "plain",
            False,
            use_key=True,
            note="sig removed from the first signed entry; kid and hash unchanged",
        ),
        Run(
            "09-wrong-kid",
            "plain",
            False,
            use_key=True,
            note="kid replaced, chain recomputed, entries re-signed with the real key",
        ),
        Run(
            "10-reordered-keys",
            "plain",
            True,
            use_key=True,
            note="top-level key order reversed; hash and sig bytes unchanged",
        ),
        Run(
            "11-u-escaped",
            "plain",
            True,
            note="non-ASCII stored as \\u escapes; parsed text is unchanged",
        ),
        Run(
            "12-lone-surrogate",
            "plain",
            False,
            note="title contains a lone \\uD800 surrogate",
        ),
        Run(
            "13-nonascii-sig",
            "plain",
            False,
            use_key=True,
            note="one signature hex digit replaced with é",
        ),
        Run(
            "14-replaced-genesis",
            "plain",
            True,
            note="genesis edited and the whole chain recomputed",
        ),
        Run(
            "14-replaced-genesis",
            "expect-old-tip",
            False,
            expect=unsigned_tip,
            note="old anchor does not match the recomputed tip",
        ),
        Run(
            "15-unsigned-with-key",
            "with-key",
            True,
            use_key=True,
            note="format spec allows an unsigned ledger; README verify does not",
        ),
    ]


def _compare(run: Run, env: dict[str, str]) -> dict[str, Any]:
    case_dir = CASES / run.case
    pub = CORPUS / PUB_NAME
    tool_cmd = [sys.executable, "-m", "audit_tool", "--root", str(CASES)]
    clean_cmd = [sys.executable, str(ROOT / "verify_ledger.py"), "--json", str(case_dir)]
    if run.use_key:
        tool_cmd.extend(["--public-key", str(pub)])
        clean_cmd.extend(["--public-key", str(pub)])
    tool_cmd.extend(["verify", run.case])
    if run.expect is not None:
        tool_cmd.extend(["--expect", run.expect])
        clean_cmd.extend(["--expect", run.expect])
    if run.exact:
        tool_cmd.append("--exact")
        clean_cmd.append("--exact")
    tool = _outcome_tool(_capture(tool_cmd, env))
    clean = _outcome_clean(_capture(clean_cmd, env))
    tool_pass = tool.status == "pass"
    clean_pass = clean.status == "pass"
    agree = tool_pass == clean_pass and tool.status != "crash" and clean.status != "crash"
    return {
        "case": run.case,
        "name": run.name,
        "note": run.note,
        "spec_ok": run.spec_ok,
        "expect": run.expect,
        "exact": run.exact,
        "use_key": run.use_key,
        "tool": _outcome_dict(tool),
        "clean": _outcome_dict(clean),
        "agree": agree,
        "tool_matches_spec": tool_pass == run.spec_ok and tool.status != "crash",
        "clean_matches_spec": clean_pass == run.spec_ok and clean.status != "crash",
    }


def _outcome_tool(captured: tuple[int | None, str]) -> Outcome:
    code, text = captured
    if code is None or "Traceback (most recent call last)" in text:
        return Outcome("crash", code, _short(text))
    status = "pass" if code == 0 else "fail"
    return Outcome(status, code, _short(text))


def _outcome_clean(captured: tuple[int | None, str]) -> Outcome:
    code, text = captured
    if code is None or "Traceback (most recent call last)" in text:
        return Outcome("crash", code, _short(text))
    codes: list[str] = []
    try:
        report = json.loads(text)
        codes = [item.get("code", "") for item in report.get("errors", [])]
        summary = ",".join(codes) if codes else "ok"
        if report.get("warnings"):
            summary += " warnings=" + ",".join(
                item.get("code", "") for item in report["warnings"]
            )
    except json.JSONDecodeError:
        summary = _short(text)
    status = "pass" if code == 0 else "fail"
    return Outcome(status, code, summary, codes)


def _outcome_dict(outcome: Outcome) -> dict[str, Any]:
    return {
        "status": outcome.status,
        "code": outcome.code,
        "summary": outcome.summary,
        "codes": outcome.codes,
    }


def _capture(cmd: list[str], env: dict[str, str]) -> tuple[int | None, str]:
    try:
        completed = subprocess.run(
            cmd,
            env=env,
            check=False,
            text=True,
            capture_output=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") + "\n" + (exc.stderr or "")
        return None, _redact(out + "\nTIMEOUT")
    text = _redact((completed.stdout or "") + (completed.stderr or ""))
    return completed.returncode, text


def _redact(text: str) -> str:
    kept: list[str] = []
    for line in text.splitlines():
        upper = line.upper()
        if "PRIVATE KEY" in upper or "BEGIN OPENSSH" in upper or "BEGIN ENCRYPTED" in upper:
            kept.append("[redacted]")
            continue
        kept.append(line)
    return "\n".join(kept)


def _short(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return " | ".join(lines[:4])[:400]


def _audit(args: list[str], env: dict[str, str]) -> None:
    _run([sys.executable, "-m", "audit_tool", *args], env)


def _run(cmd: list[str], env: dict[str, str]) -> None:
    completed = subprocess.run(cmd, env=env, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        message = _redact((completed.stdout or "") + (completed.stderr or ""))
        raise SystemExit(f"command failed ({completed.returncode}): {cmd[0:6]}\n{message}")


def _confirm_head(work: Path, anchors: dict[str, str], env: dict[str, str]) -> None:
    for case_id, anchor in anchors.items():
        completed = subprocess.run(
            [sys.executable, "-m", "audit_tool", "--root", str(work), "head", case_id],
            env=env,
            check=False,
            text=True,
            capture_output=True,
        )
        if completed.returncode != 0 or completed.stdout.strip() != anchor:
            raise SystemExit(f"head mismatch for {case_id}")


def _copy(src: str, dest: str) -> None:
    shutil.copytree(CASES / src, CASES / dest)


def _read(case: Path) -> list[dict[str, Any]]:
    ledger = case / "ledger.jsonl"
    return [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines() if line]


def _write(case: Path, entries: list[dict[str, Any]]) -> None:
    text = "\n".join(_dump(entry) for entry in entries) + "\n"
    (case / "ledger.jsonl").write_text(text, encoding="utf-8")


def _dump(entry: dict[str, Any]) -> str:
    ordered = {key: entry[key] for key in FIELD_ORDER if key in entry}
    for key in entry:
        if key not in ordered:
            ordered[key] = entry[key]
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def _tip(case: Path) -> str:
    last = _read(case)[-1]
    return f"{last['seq']}:{last['hash']}"


def _edit_field(case: Path) -> None:
    ledger = case / "ledger.jsonl"
    text = ledger.read_text(encoding="utf-8")
    old = "Résumé"
    if old not in text:
        raise SystemExit("edited-field target not found")
    ledger.write_text(text.replace(old, "Resume", 1), encoding="utf-8")


def _swap_middle(case: Path) -> None:
    entries = _read(case)
    if len(entries) < 7:
        raise SystemExit("need a longer ledger to swap a middle entry")
    left, right = entries[4], entries[5]
    left["payload"], right["payload"] = right["payload"], left["payload"]
    left["kind"], right["kind"] = right["kind"], left["kind"]
    for entry in (left, right):
        entry["hash"] = entry_hash(entry)
    _write(case, entries)


def _truncate_tail(case: Path) -> None:
    entries = _read(case)
    if len(entries) < 3:
        raise SystemExit("ledger too short to truncate")
    _write(case, entries[:-2])


def _append_entry(case: Path) -> None:
    entries = _read(case)
    last = entries[-1]
    entry: dict[str, Any] = {
        "seq": last["seq"] + 1,
        "ts": "2026-10-22T12:00:00+00:00",
        "kind": "event.add",
        "payload": {
            "id": "EVT-9001",
            "source_type": "note",
            "decision": "Noted",
            "reason": "appended after the anchor",
            "evidence_status": "unverified",
            "origin": {},
            "artifacts": [],
            "automated": "unknown",
            "human_involved": "unknown",
            "notice_provided": "unknown",
            "reproducible": "unknown",
        },
        "prev": last["hash"],
    }
    entry["hash"] = entry_hash(entry)
    entries.append(entry)
    _write(case, entries)


_SIG_RE = re.compile(r',\s*"sig"\s*:\s*"([0-9a-f]{128})"')


def _strip_earliest_sig(case: Path) -> None:
    ledger = case / "ledger.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        match = _SIG_RE.search(line)
        if match is None:
            continue
        lines[index] = line[: match.start()] + line[match.end() :]
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return
    raise SystemExit("no signature to strip")


def _apply_wrong_kid(case: Path, private_key: Ed25519PrivateKey) -> None:
    entries = _read(case)
    target = next(index for index, entry in enumerate(entries) if "sig" in entry)
    entries[target]["kid"] = "0000000000000000"
    for index in range(target, len(entries)):
        if index == 0:
            entries[index]["prev"] = GENESIS_PREV
        else:
            entries[index]["prev"] = entries[index - 1]["hash"]
        entries[index]["hash"] = entry_hash(entries[index])
        if "sig" in entries[index]:
            signature = private_key.sign(entries[index]["hash"].encode("ascii"))
            entries[index]["sig"] = signature.hex()
    _write(case, entries)


def _reorder_keys(case: Path) -> None:
    # Reverse only the top-level key order. Nested objects stay dicts, and
    # separators stay the ones the CLI writes, so the hash input is the
    # same object.
    ledger = case / "ledger.jsonl"
    lines_out: list[str] = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise SystemExit("ledger line is not an object")
        reversed_obj = {key: obj[key] for key in reversed(list(obj))}
        lines_out.append(json.dumps(reversed_obj, ensure_ascii=False))
    ledger.write_text("\n".join(lines_out) + "\n", encoding="utf-8")


def _escape_unicode(case: Path) -> None:
    ledger = case / "ledger.jsonl"
    lines_out: list[str] = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        obj = json.loads(line)
        lines_out.append(json.dumps(obj, ensure_ascii=True))
    text = "\n".join(lines_out) + "\n"
    if "\\u" not in text:
        raise SystemExit("unicode escape tamper produced no \\u escapes")
    ledger.write_text(text, encoding="utf-8")


def _inject_surrogate(case: Path) -> None:
    ledger = case / "ledger.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    match = re.search(r'"title"\s*:\s*"', lines[0])
    if match is None:
        raise SystemExit("title field not on the genesis line")
    end = lines[0].find('"', match.end())
    if end == -1:
        raise SystemExit("title string is not closed")
    lines[0] = lines[0][:end] + "\\uD800" + lines[0][end:]
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _nonascii_sig(case: Path) -> None:
    ledger = case / "ledger.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        match = _SIG_RE.search(line)
        if match is None:
            continue
        digit = match.start(1)
        lines[index] = line[:digit] + "é" + line[digit + 1 :]
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return
    raise SystemExit("no signature to alter")


def _replace_genesis(case: Path) -> None:
    entries = _read(case)
    title = entries[0]["payload"].get("title")
    if not isinstance(title, str):
        raise SystemExit("genesis has no title")
    entries[0]["payload"]["title"] = title + " [replaced]"
    for index, entry in enumerate(entries):
        if index == 0:
            entry["prev"] = GENESIS_PREV
        else:
            entry["prev"] = entries[index - 1]["hash"]
        entry.pop("sig", None)
        entry.pop("kid", None)
        entry["hash"] = entry_hash(entry)
    _write(case, entries)


def _chmod_public(path: Path) -> None:
    for item in path.rglob("*"):
        mode = item.stat().st_mode
        if item.is_dir():
            item.chmod(mode | 0o755)
        else:
            item.chmod(mode | 0o644)


def _wipe(path: Path) -> None:
    if not path.exists():
        return
    size = path.stat().st_size
    path.write_bytes(b"\x00" * size)
    path.unlink()


if __name__ == "__main__":
    sys.exit(main())
