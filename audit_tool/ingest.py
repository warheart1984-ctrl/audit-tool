"""Turn raw artifacts (emails, letters, transcripts, chat logs, CSVs, screenshots, PDFs) into events.

Everything pulled out here is a heuristic guess and is marked `extracted`.
A person should review each event and confirm or correct it with `audit edit`;
the report shows which facts are confirmed and which are machine-extracted.
"""

from __future__ import annotations

import csv
import email
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy as email_policy
from email.utils import parsedate_to_datetime
from pathlib import Path

from .extract import ExtractedText, extract, extract_isolated

TEXT_EXT = {".txt", ".md", ".log"}
EMAIL_EXT = {".eml"}
CSV_EXT = {".csv", ".tsv"}
PDF_EXT = {".pdf"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

# Evidence is untrusted input; bound the work any one file can cause.
MAX_TEXT_BYTES = 20 * 1024 * 1024  # emails, letters, transcripts
MAX_CSV_BYTES = 50 * 1024 * 1024
MAX_PDF_BYTES = 100 * 1024 * 1024
MAX_IMAGE_BYTES = 50 * 1024 * 1024
MAX_CSV_ROWS = 100_000

# 550 5.7.193 / 550.5.7.193 / 554-5.7.1
SMTP_CODE = re.compile(r"\b([245]\d\d)[\s.\-]?([245]\.\d{1,3}\.\d{1,3})\b")
REASON_CODE = re.compile(r"\b(?:reason|error|decline|denial|response)\s*code[:#\s]*([A-Z0-9][A-Z0-9.\-]{1,20})\b", re.I)

DECISION_WORDS = {
    "rejected": "Rejected", "reject": "Rejected", "denied": "Denied", "deny": "Denied",
    "declined": "Declined", "blocked": "Blocked", "suspended": "Suspended",
    "frozen": "Frozen", "closed": "Closed", "restricted": "Restricted",
    "on hold": "Placed on hold", "held": "Placed on hold", "reversed": "Reversed",
    "terminated": "Terminated", "undeliverable": "Rejected (undeliverable)",
    "couldn't be delivered": "Rejected (undeliverable)", "could not be delivered": "Rejected (undeliverable)",
    "wasn't delivered": "Rejected (undeliverable)", "sender not allowed": "Rejected (sender not allowed)",
    "approved": "Approved",
}
# Line-oriented reasons, matched against the raw text.
LINE_REASONS = [
    re.compile(r"remote server returned\s*['\"]?(?:[245]\d\d[\s.\-]?[245]\.\d{1,3}\.\d{1,3}\s*)?([^'\"\n]+)", re.I),
    re.compile(r"(?:^|\n)\s*(?:reason|diagnostic[- ]code)\s*[:\-]\s*(.+)", re.I),
]
# Bounce notices state the rule in a full sentence, e.g. Microsoft 365's
# "The group X is configured to reject messages sent to it from outside its organization".
# Most specific first.
# \s* rather than \s+ because OCR of phone screenshots often drops the spaces between words.
BOUNCE_RULES = [
    re.compile(r"is\s*configured\s*to\s*reject", re.I),
    re.compile(r"blocked\s*by\s*(?:the\s*)?(?:recipient|organization)", re.I),
    re.compile(r"(?:isn't|is\s*not)\s*(?:allowed\s*to\s*send|set\s*up\s*to\s*receive)", re.I),
]
# Prose reasons, matched against whitespace-flattened text so line wraps don't cut them.
PROSE_REASON = re.compile(r"\b(?:because|due to|as a result of)\s+([^.]{5,200})", re.I)
POLICY_PATTERNS = [
    re.compile(r"\b(?:section|clause|paragraph)\s*\d+(?:\.\d+)*[^.\n]{0,80}", re.I),
    re.compile(r"\b(?:our|the|bank'?s?)\s+[\w\s]{0,30}?(?:policy|policies|terms(?: and conditions)?|agreement)\b[^.\n]{0,80}", re.I),
    re.compile(r"\b(?:Regulation\s+[A-Z]{1,2}|\d+\s+(?:CFR|U\.S\.C\.)\s+[\d.§]+|§\s*[\d.]+)[^.\n]{0,60}"),
]
AUTOMATION_SIGNS = re.compile(
    r"\b(no-?reply|do not reply|automated|automatically|auto-generated|system generated|"
    r"mailer-daemon|postmaster|risk (?:model|engine|score)|algorithm|our systems?)\b", re.I)
# Signs that a person reviewed the decision, not merely that a person answered the phone.
HUMAN_SIGNS = re.compile(
    r"\b(reviewed by|I have reviewed|we have reviewed|after (?:careful |manual )?review|"
    r"manually reviewed|case (?:manager|officer)|underwriter)\b", re.I)
# Lines spoken by the customer are not statements by the institution.
CUSTOMER_LINE = re.compile(r"^\s*(?:\[?[\d:]+\]?\s*)?(customer|caller|me)\s*:", re.I)
APPEAL_PATTERN = re.compile(
    r"[^.\n]*\b(appeal|dispute|reconsider|request (?:a|another) review|escalat|complaint|ombudsman|CFPB)\b[^.\n]*", re.I)

# "Label: value" lines, as found in bounce notices and letter headers.
# OCR often drops the space after the colon, hence \s*.
LABELS = {
    "sender": r"(?:Sender\s*Address|Sender|From)",
    "recipient": r"(?:Recipient\s*Address|Recipient|To)",
    "timestamp": r"(?:Created\s*Date|Date\s*Sent|Sent|Date)",
    "subject": r"(?:Subject|Re)",
}
LABEL_LINE = re.compile(r"^\s*[A-Za-z][A-Za-z ]{1,25}:")
MAIL_SYSTEMS = [
    (re.compile(r"Microsoft\s*365|Office\s*365|Exchange\s*Online|outlook\.com", re.I), "Microsoft 365 (Exchange Online)"),
    # Not plain "gmail": a gmail.com sender address says nothing about who bounced the message.
    (re.compile(r"Mail\s*Delivery\s*Subsystem|mailer-daemon@googlemail", re.I), "Gmail"),
]

MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December"
DATE_PATTERNS = [
    re.compile(r"\b(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?"),
    # 10/21/2026 9:38:40 PM, also OCR'd as 10/21/20269:38:40PM
    re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{4})\s*(?:(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp][Mm])?)?"),
    re.compile(rf"\b({MONTHS})\s*(\d{{1,2}}),?\s*(\d{{4}})", re.I),
]


@dataclass
class IngestResult:
    events: list[dict]
    extracted: ExtractedText | None = None  # text recovered by OCR/PDF extraction
    warnings: list[str] = field(default_factory=list)


def find_date(text: str) -> str:
    """First date in `text`, as ISO 8601. Slash dates are read month/day (Microsoft's US default)."""
    for i, pat in enumerate(DATE_PATTERNS):
        m = pat.search(text)
        if not m:
            continue
        g = m.groups()
        try:
            if i == 0:
                dt = datetime(int(g[0]), int(g[1]), int(g[2]), int(g[3] or 0), int(g[4] or 0), int(g[5] or 0))
            elif i == 1:
                hour = int(g[3] or 0)
                if g[6] and g[6].lower() == "pm" and hour < 12:
                    hour += 12
                elif g[6] and g[6].lower() == "am" and hour == 12:
                    hour = 0
                dt = datetime(int(g[2]), int(g[0]), int(g[1]), hour, int(g[4] or 0), int(g[5] or 0))
            else:
                dt = datetime.strptime(f"{g[0]} {g[1]} {g[2]}", "%B %d %Y")
        except ValueError:
            continue
        return dt.isoformat()
    return ""


def normalize_date(value: str) -> str:
    return find_date(value) or value


def detect_type(path: Path, override: str | None = None) -> str:
    if override:
        return override
    ext = path.suffix.lower()
    if ext in EMAIL_EXT:
        return "email"
    if ext in CSV_EXT:
        return "transaction"
    if ext in IMAGE_EXT:
        return "screenshot"
    if ext in PDF_EXT:
        return "letter"
    if ext in TEXT_EXT:
        with path.open("rb") as fh:
            head = fh.read(2000).decode("utf-8", errors="replace")
        if re.search(r"^(From|To|Subject|Date):", head, re.M):
            return "email"
        if re.search(r"^\s*\[?\d{1,2}:\d{2}", head, re.M) and re.search(r"^\s*[\w .]+:\s", head, re.M):
            return "chat"
        if re.search(r"^\s*(Agent|Representative|Customer|Caller|Rep)\s*:", head, re.M | re.I):
            return "transcript"
        return "letter"
    return "other"


def _first(patterns, text: str) -> str:
    for pat in patterns:
        m = pat.search(text)
        if m:
            return " ".join((m.group(1) if m.groups() else m.group(0)).split())[:300]
    return ""


def _sentence_around(text: str, start: int, end: int) -> str:
    """The sentence containing text[start:end], flattened to one line.

    Periods inside addresses don't end a sentence. A line break before a capital
    letter does, which separates headings ("Status code: ...") from the body text.
    """
    boundaries = [m.end() for m in re.finditer(r"[.!?](?=\s|$)|\n(?=\s*[A-Z])", text)]
    begin = max((b for b in boundaries if b <= start), default=0)
    finish = min((b for b in boundaries if b >= end), default=len(text))
    return " ".join(text[begin:finish].split())[:400]


def _labelled(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    lines = text.splitlines()
    for name, label in LABELS.items():
        pat = re.compile(rf"^\s*{label}\s*:\s*(.+)$", re.I)
        for i, line in enumerate(lines):
            m = pat.match(line)
            if not m:
                continue
            value = m.group(1).strip()
            # Wrapped subject lines continue on the next non-label line.
            if name == "subject" and i + 1 < len(lines):
                nxt = lines[i + 1].strip()
                if nxt and not LABEL_LINE.match(nxt):
                    value = f"{value} {nxt}"
            out[name] = find_date(value) or value if name == "timestamp" else value
            break
    return out


def analyze_text(text: str) -> dict:
    """Extract decision-related facts from free text."""
    out: dict[str, str] = {}
    flat = " ".join(text.split())
    low = flat.lower()

    smtp = SMTP_CODE.search(text)
    if smtp:
        out["status_code"] = f"{smtp.group(1)} {smtp.group(2)}"
    elif m := REASON_CODE.search(text):
        out["status_code"] = m.group(1)

    hits = [(low.find(w), label) for w, label in DECISION_WORDS.items() if re.search(rf"\b{re.escape(w)}\b", low)]
    if not hits:
        # OCR may have run words together ("couldn'tbedelivered"). Only multi-word phrases are
        # safe to match without word boundaries; "closed" would match inside "disclosed".
        squashed = "".join(low.split())
        hits = [(squashed.find(w.replace(" ", "")), label) for w, label in DECISION_WORDS.items()
                if " " in w and w.replace(" ", "") in squashed]
    if hits:
        out["decision"] = min(hits)[1]

    reason = _first(LINE_REASONS, text)
    if not reason:
        for pat in BOUNCE_RULES:
            if m := pat.search(text):
                reason = _sentence_around(text, m.start(), m.end())
                break
    if reason or (reason := _first([PROSE_REASON], flat)):
        out["reason"] = reason
    if policy := _first(POLICY_PATTERNS, flat):
        out["policy_cited"] = policy

    auto, human = AUTOMATION_SIGNS.search(text), HUMAN_SIGNS.search(text)
    if human:
        out["human_involved"] = "yes"
    elif auto or (smtp and smtp.group(1)[0] in "45"):
        # A mail server rejecting with a 4xx/5xx code is applying a configured rule automatically.
        out["automated"] = "yes"
        out["human_involved"] = "no"

    for appeal in APPEAL_PATTERN.finditer(text):
        if not CUSTOMER_LINE.match(appeal.group(0)):
            out["appeal_path"] = " ".join(appeal.group(0).split())[:300]
            break

    out.update(_labelled(text))
    if smtp:
        for pat, name in MAIL_SYSTEMS:
            if pat.search(text):
                out["source"] = name
                break
        # A bounce notice is itself notice that the message was refused.
        out["notice_provided"] = "yes"
        if out.get("recipient"):
            out["request"] = f"Send email to {out['recipient']}" + (f": {out['subject']}" if out.get("subject") else "")
    return out


def _mark(fields_: dict) -> dict:
    fields_["origin"] = {k: "extracted" for k in fields_ if k != "origin" and fields_[k]}
    return fields_


def analyze_document(text: str, source_type: str) -> dict:
    fields_ = analyze_text(text)
    fields_["source_type"] = source_type
    if not fields_.get("timestamp") and (date := find_date(text)):
        fields_["timestamp"] = date
    if source_type == "letter" and fields_.get("decision"):
        fields_["notice_provided"] = "yes"
    return fields_


def ingest_email(path: Path) -> list[dict]:
    raw = path.read_bytes()
    msg = email.message_from_bytes(raw, policy=email_policy.default)
    parts = []
    for part in msg.walk():
        if part.get_content_maintype() == "text":
            try:
                parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                parts.append(part.get_payload(decode=True).decode("utf-8", errors="replace"))
        elif part.get_content_type() == "message/delivery-status":
            parts.append(str(part.get_payload()[0]) if part.get_payload() else "")
    body = "\n".join(p for p in parts if p) or raw.decode("utf-8", errors="replace")

    fields_ = analyze_text(f"{msg.get('Subject', '')}\n{body}")
    fields_["source_type"] = "email"
    headers = {"sender": str(msg.get("From", "")), "recipient": str(msg.get("To", "")),
               "subject": str(msg.get("Subject", ""))}
    if msg.get("Date"):
        try:
            headers["timestamp"] = parsedate_to_datetime(str(msg["Date"])).isoformat()
        except (TypeError, ValueError):
            headers["timestamp"] = str(msg["Date"])
    if fields_.get("status_code"):
        # A bounce: the body's "Original Message Details" describe the refused message;
        # the headers only describe the bounce itself.
        for name, value in headers.items():
            fields_.setdefault(name, value)
        fields_.setdefault("source", "Mail system (delivery status notification)")
        fields_.setdefault("request", f"Send email to {fields_['recipient']}".strip())
    else:
        fields_.update({k: v for k, v in headers.items() if v})
    if AUTOMATION_SIGNS.search(headers["sender"]):
        fields_["automated"] = "yes"
    # An email received from the institution is itself notice of the decision.
    if fields_.get("decision"):
        fields_["notice_provided"] = "yes"
    return [_mark(fields_)]


def ingest_text(path: Path, source_type: str) -> list[dict]:
    if source_type == "email":
        return ingest_email(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return [_mark(analyze_document(text, source_type))]


def _col(row: dict, *names: str) -> str:
    lowered = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
    for n in names:
        if lowered.get(n):
            return lowered[n]
    return ""


STATUS_COLUMNS = ("status", "result", "decision", "state")


def ingest_csv(path: Path) -> tuple[list[dict], list[str]]:
    """One event per row whose status is anything other than a plain success."""
    warnings: list[str] = []
    with path.open(encoding="utf-8-sig", newline="") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        try:
            delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
        reader = csv.DictReader(fh, delimiter=delimiter)
        headers = {h.strip().lower() for h in (reader.fieldnames or []) if h}
        if not headers & set(STATUS_COLUMNS):
            # Without a status column every row would be skipped, silently reporting "nothing adverse".
            return [], [f"no status column found (looked for {', '.join(STATUS_COLUMNS)}; "
                        f"columns are: {', '.join(sorted(headers)) or 'none'}); nothing ingested"]
        events = []
        rows = enumerate(reader, start=2)
        while True:
            try:
                i, row = next(rows)
            except StopIteration:
                break
            except csv.Error as exc:  # e.g. a field over the csv module's size limit
                warnings.append(f"stopped at line {reader.line_num}: {exc}; the rest were not read")
                break
            if i - 1 > MAX_CSV_ROWS:
                warnings.append(f"stopped after {MAX_CSV_ROWS} rows; the rest were not read")
                break
            status = _col(row, *STATUS_COLUMNS)
            if status.lower() in ("", "posted", "completed", "complete", "success", "settled", "approved", "cleared"):
                continue
            desc = _col(row, "description", "merchant", "payee", "memo", "details")
            amount = _col(row, "amount", "value", "debit", "credit")
            fields_ = {
                "source_type": "transaction",
                "timestamp": normalize_date(_col(row, "date", "timestamp", "posted", "time", "transaction date")),
                "request": " ".join(x for x in (desc, amount) if x),
                "decision": status.capitalize(),
                "status_code": _col(row, "code", "reason code", "decline code", "response code"),
                "reason": _col(row, "reason", "decline reason", "message", "note"),
                "notes": f"CSV row {i}",
            }
            events.append(_mark({k: v for k, v in fields_.items() if v}))
    return events, warnings


def ingest_binary(path: Path, kind: str, use_ocr: bool = True, isolate: bool = True) -> IngestResult:
    """Screenshots and PDFs: recover text with OCR / the PDF text layer, then analyse it."""
    if not use_ocr:
        return IngestResult([{"source_type": kind, "origin": {},
                              "notes": "Binary artifact preserved (text extraction skipped). Enter its facts with `audit edit`."}])
    ex = extract_isolated(path) if isolate else extract(path)
    if not ex.text.strip():
        note = "Binary artifact preserved; no text could be extracted. Enter its facts with `audit edit`."
        if ex.warnings:
            note += " (" + "; ".join(ex.warnings) + ")"
        return IngestResult([{"source_type": kind, "notes": note, "origin": {}}], ex, ex.warnings)
    fields_ = _mark(analyze_document(ex.text, kind))
    fields_["notes"] = ex.summary()
    return IngestResult([fields_], ex, ex.warnings)


def _size_limit(ext: str) -> int | None:
    if ext in EMAIL_EXT | TEXT_EXT:
        return MAX_TEXT_BYTES
    if ext in CSV_EXT:
        return MAX_CSV_BYTES
    if ext in PDF_EXT:
        return MAX_PDF_BYTES
    if ext in IMAGE_EXT:
        return MAX_IMAGE_BYTES
    return None


def ingest_file(path: Path, source_type: str | None = None, use_ocr: bool = True,
                isolate: bool = True) -> IngestResult:
    result = _ingest(path, source_type, use_ocr, isolate)
    # Anything that limited or degraded the extraction belongs in the record,
    # not only on the screen at ingest time.
    if result.warnings:
        note = "Ingest warnings: " + "; ".join(result.warnings)
        for ev in result.events:
            ev["notes"] = f"{ev['notes']} {note}" if ev.get("notes") else note
    return result


def _ingest(path: Path, source_type: str | None, use_ocr: bool, isolate: bool) -> IngestResult:
    ext = path.suffix.lower()
    size = path.stat().st_size
    limit = _size_limit(ext)
    if limit is not None and size > limit:
        return IngestResult([{"source_type": source_type or detect_type(path), "origin": {},
                              "notes": f"File too large for automatic extraction ({size} bytes). "
                                       "Preserved as evidence; enter its facts with `audit edit`."}],
                            warnings=[f"{size} bytes exceeds the {limit}-byte limit for {ext} files; not parsed"])
    kind = detect_type(path, source_type)
    if ext in CSV_EXT:
        events, warnings = ingest_csv(path)
        return IngestResult(events, warnings=warnings)
    if ext in EMAIL_EXT:
        return IngestResult(ingest_email(path))
    if ext in TEXT_EXT:
        return IngestResult(ingest_text(path, kind))
    if ext in IMAGE_EXT or ext in PDF_EXT:
        return ingest_binary(path, kind, use_ocr, isolate)
    return IngestResult([{"source_type": kind, "origin": {},
                          "notes": "Unrecognised file type preserved. Enter its facts with `audit edit`."}])
