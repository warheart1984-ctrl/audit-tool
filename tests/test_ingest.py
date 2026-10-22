"""Parsing limits (F5), CSV delimiter detection, and bounce-notice extraction."""

from __future__ import annotations

from audit_tool import ingest
from audit_tool.ingest import analyze_text, ingest_file


def test_semicolon_csv_is_detected(tmp_path):
    f = tmp_path / "statement.csv"
    f.write_text("Date;Description;Amount;Status;Reason\n2026-01-01;Rent;-1200;Declined;Account frozen\n")
    result = ingest_file(f)
    assert len(result.events) == 1
    assert result.events[0]["decision"] == "Declined"
    assert result.events[0]["reason"] == "Account frozen"


def test_csv_without_status_column_warns_instead_of_reporting_nothing(tmp_path):
    f = tmp_path / "statement.csv"
    f.write_text("Date,Description,Amount\n2026-01-01,Rent,-1200\n")
    result = ingest_file(f)
    assert result.events == []
    assert any("no status column" in w for w in result.warnings)


def test_csv_row_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_CSV_ROWS", 2)
    f = tmp_path / "statement.csv"
    f.write_text("Date,Status\n" + "2026-01-01,Declined\n" * 5)
    result = ingest_file(f)
    assert len(result.events) == 2
    assert any("stopped after 2 rows" in w for w in result.warnings)


def test_oversized_text_file_is_not_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest, "MAX_TEXT_BYTES", 100)
    f = tmp_path / "letter.txt"
    f.write_text("Your account was restricted. " * 20)
    result = ingest_file(f)
    assert len(result.events) == 1 and "decision" not in result.events[0]
    assert any("-byte limit for .txt files" in w for w in result.warnings)


def test_bounce_text_with_ocr_dropped_spaces():
    # Shape of real RapidOCR output from a phone screenshot of a Microsoft 365 bounce.
    text = (
        "YourmessagetotheMicrosoft365groupgroup@agency.example.cacouldn'tbe\n"
        "delivered.\n"
        "Statuscode:5505.7.193\n"
        "TheMicrosoft365group,group@agency.example.ca,isconfiguredtorejectmessagessentto\n"
        "it fromoutsideitsorganization-unless thesenderis a guest groupmember.\n"
        "Created Date: 10/21/20269:38:40PM\n"
        "Sender Address: sender@gmail.com\n"
        "RecipientAddress: group@agency.example.ca\n"
    )
    out = analyze_text(text)
    assert out["decision"] == "Rejected (undeliverable)"
    assert out["status_code"] == "550 5.7.193"
    assert out["source"] == "Microsoft 365 (Exchange Online)"  # not "Gmail" from the sender address
    assert out["recipient"] == "group@agency.example.ca"
    assert out["sender"] == "sender@gmail.com"
    assert out["timestamp"] == "2026-10-21T21:38:40"
    assert "isconfiguredtoreject" in out["reason"]
    assert out["automated"] == "yes" and out["notice_provided"] == "yes"


def test_squashed_matching_does_not_hit_short_words_inside_others():
    assert "decision" not in analyze_text("The fee was disclosed in your statement.")


def test_customer_lines_are_not_read_as_an_appeal_path():
    out = analyze_text("Customer: Can I appeal?\nAgent: You can file a dispute through the portal.")
    assert out["appeal_path"].startswith("Agent:")
