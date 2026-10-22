"""Third review: read commands fail closed, owner-only permissions, byte limits,
isolated parsing, evidence-folder redirection, and recorded warnings."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from audit_tool import extract as ex
from audit_tool import ingest
from audit_tool.ingest import ingest_file
from audit_tool.models import Event
from audit_tool.secure import windows_acl_entries

REPO = Path(__file__).resolve().parents[1]


def _tamper_decision(ledger: Path) -> None:
    lines = ledger.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        entry = json.loads(line)
        if entry["kind"] == "event.add":
            entry["payload"]["decision"] = "Approved"
            lines[i] = json.dumps(entry)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --- 1. Read commands must not present a forged ledger as a clean audit -------------

def test_check_show_report_list_fail_closed_on_tampered_ledger(cli, tmp_path):
    cli("new", "c", "--title", "t")
    cli("add", "c", "--set", "decision=Declined")
    _tamper_decision(tmp_path / "cases" / "c" / "ledger.jsonl")

    code, out = cli("check", "c")
    assert code == 2 and "INTEGRITY FAILED" in out and "No findings" not in out
    code, out = cli("show", "c", "EVT-0001")
    assert code == 2 and "Approved" not in out
    code, out = cli("report", "c")
    assert code == 2 and "WARNING: INTEGRITY FAILED" in out.split("## Summary")[0]
    code, out = cli("list")
    assert "INTEGRITY FAILED" in out


def test_unverified_flag_shows_results_with_a_warning(cli, tmp_path):
    cli("new", "c", "--title", "t")
    cli("add", "c", "--set", "decision=Declined")
    _tamper_decision(tmp_path / "cases" / "c" / "ledger.jsonl")
    code, out = cli("show", "c", "EVT-0001", "--unverified")
    assert code == 0 and out.startswith("WARNING: case c FAILS integrity verification")


# --- 4. Owner-only permissions ------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_case_files_are_owner_only_on_posix(cli, tmp_path):
    cli("new", "c", "--title", "t")
    f = tmp_path / "letter.txt"
    f.write_text("Your account has been restricted.")
    cli("ingest", "c", str(f))
    case = tmp_path / "cases" / "c"
    for p in [tmp_path / "cases", case, case / "evidence"]:
        assert stat.S_IMODE(p.stat().st_mode) == 0o700, p
    for p in [case / "ledger.jsonl", *(case / "evidence").iterdir()]:
        assert stat.S_IMODE(p.stat().st_mode) == 0o600, p


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_secure_tightens_an_existing_case_on_posix(cli, tmp_path):
    cli("new", "c", "--title", "t")
    case = tmp_path / "cases" / "c"
    os.chmod(case, 0o755)
    os.chmod(case / "ledger.jsonl", 0o644)
    assert "readable by other accounts" in cli("verify", "c")[1]
    cli("secure", "c")
    assert stat.S_IMODE(case.stat().st_mode) == 0o700
    assert stat.S_IMODE((case / "ledger.jsonl").stat().st_mode) == 0o600


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACLs")
def test_case_folder_acl_is_owner_and_system_only_on_windows(cli, tmp_path):
    cli("new", "c", "--title", "t")
    acl = windows_acl_entries(tmp_path / "cases" / "c")
    assert "Authenticated Users" not in acl and "BUILTIN\\Users" not in acl and "Everyone" not in acl
    assert "SYSTEM" in acl
    assert "(I)" not in acl  # nothing inherited from the drive


def test_private_key_is_owner_only(cli, tmp_path):
    pytest.importorskip("cryptography")
    key = tmp_path / "k" / "audit.key"
    assert cli("keygen", str(key))[0] == 0
    if sys.platform == "win32":
        acl = windows_acl_entries(key)
        assert "Authenticated Users" not in acl and "BUILTIN\\Users" not in acl
        assert "(I)" not in acl  # explicit owner-only ACL, not whatever the parent folder grants
    else:
        assert stat.S_IMODE(key.stat().st_mode) == 0o600


# --- 5. Parser libraries must not be capped below security releases -----------------

def test_dependency_pins_allow_security_releases():
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    ocr = re.search(r"ocr = \[(.*?)\]", text, re.S).group(1)
    assert '"Pillow>=13.0.0"' in ocr
    assert '"pypdf>=6.21.2"' in ocr  # CVE-2026-113786 (6.21.1) and the xref runtime advisories (6.21.2)
    assert "<" not in ocr, "upper bounds on parser libraries block security fixes"


# --- 6. Byte limits and isolated parsing ------------------------------------------

@pytest.mark.parametrize("name,attr", [("big.pdf", "MAX_PDF_BYTES"), ("big.png", "MAX_IMAGE_BYTES"),
                                       ("big.csv", "MAX_CSV_BYTES")])
def test_every_parsed_type_has_a_byte_limit(tmp_path, monkeypatch, name, attr):
    monkeypatch.setattr(ingest, attr, 10)
    f = tmp_path / name
    f.write_bytes(b"x" * 100)
    result = ingest_file(f, isolate=False)
    assert any(f"limit for {f.suffix} files; not parsed" in w for w in result.warnings)
    assert "too large" in result.events[0]["notes"]


def test_oversized_csv_field_is_a_warning_not_a_crash(tmp_path):
    f = tmp_path / "s.csv"
    f.write_text("Date,Status,Reason\n2026-01-01,Declined,ok\n2026-01-02,Declined," + "A" * 300_000 + "\n")
    result = ingest_file(f)
    assert len(result.events) == 1  # the row before the bad one is kept
    assert any("field larger than field limit" in w for w in result.warnings)


def _sleep_child(conn):
    time.sleep(60)


def _crash_child(conn):
    os._exit(3)


def _env_child(conn):
    conn.send(os.environ.get("AUDIT_KEY_FILE"))
    conn.close()


def test_isolated_extraction_times_out():
    start = time.monotonic()
    with pytest.raises(RuntimeError, match="timed out"):
        ex.run_isolated(_sleep_child, (), timeout=3)
    assert time.monotonic() - start < 30


def test_isolated_extraction_survives_a_crashing_decoder():
    with pytest.raises(RuntimeError, match="crashed"):
        ex.run_isolated(_crash_child, (), timeout=30)


def test_key_path_is_not_passed_to_the_extraction_process(monkeypatch):
    monkeypatch.setenv("AUDIT_KEY_FILE", "/secret/audit.key")
    assert ex.run_isolated(_env_child, (), timeout=30) is None
    assert os.environ["AUDIT_KEY_FILE"] == "/secret/audit.key"  # restored in the parent


def test_extract_isolated_returns_results_from_the_child(tmp_path):
    f = tmp_path / "broken.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\nnot really")
    result = ex.extract_isolated(f, timeout=60)
    assert result.text == "" and any("could not read file" in w for w in result.warnings)


# --- Mediums -------------------------------------------------------------------------

def _link_dir(link: Path, target: Path) -> None:
    if sys.platform == "win32":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        if r.returncode:
            pytest.skip("could not create a junction")
    else:
        os.symlink(target, link)


def test_evidence_folder_redirect_is_refused_before_writing(ws, tmp_path):
    case = ws.create_case("c", "t")
    outside = tmp_path / "outside"
    outside.mkdir()
    _link_dir(case.evidence_dir, outside)
    src = tmp_path / "letter.txt"
    src.write_text("Your account has been restricted.")
    with pytest.raises(ValueError, match="link or junction"):
        case.store_artifact(src)
    assert list(outside.iterdir()) == []
    assert any("link or junction" in p for p in case.verify())


def test_existing_evidence_name_with_other_content_is_not_trusted(ws, tmp_path):
    case = ws.create_case("c", "t")
    src = tmp_path / "letter.txt"
    src.write_text("original")
    art = case.store_artifact(src)
    (case.dir / art["stored_path"]).write_text("swapped")
    with pytest.raises(ValueError, match="different content"):
        case.store_artifact(src)


def test_ingest_warnings_are_saved_with_the_event(cli, tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_CSV_ROWS", 1)
    cli("new", "c", "--title", "t")
    f = tmp_path / "s.csv"
    f.write_text("Date,Status\n2026-01-01,Declined\n2026-01-02,Declined\n")
    cli("ingest", "c", str(f))
    code, out = cli("show", "c", "EVT-0001")
    assert "Ingest warnings: stopped after 1 rows" in out


def test_no_adverse_record_is_covered_by_the_evidence_sweep(ws, tmp_path):
    case = ws.create_case("c", "t")
    src = tmp_path / "ok.csv"
    src.write_text("Date,Status\n2026-01-01,Posted\n")
    case.record_artifact(case.store_artifact(src), "No adverse decisions found.")
    assert case.verify() == []
    (case.dir / case.records()[0]["artifact"]["stored_path"]).write_text("changed")
    assert any("changed since it was recorded" in p for p in case.verify())


def test_malformed_record_entry_is_reported(ws):
    case = ws.create_case("c", "t")
    case.add_event(Event(id="EVT-0001"))
    case.ledger.append("artifact.record", {"artifact": "x"})
    assert any("artifact.record ignored" in p for p in case.verify())
