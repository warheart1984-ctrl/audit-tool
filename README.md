# Audit tool

Builds a case file around automated decisions, such as rejected emails, declined payments or restricted accounts. It shifts the claim from *"I think the bank treated me unfairly"* to findings like these:

```text
Decision EVT-0004 (Declined, R16) on 2026-10-10.
No human review record has been provided.
No supporting evidence was provided for the decision.
No appeal path was disclosed.
```

It needs Python 3.10+. The core has no dependencies. To read text from screenshots and PDF letters, install the OCR extras:

```bash
pip install -e ".[ocr]"
```

That installs RapidOCR, which ships its own models, so no system OCR program is needed. If RapidOCR is missing, Tesseract is used when `pytesseract` and the `tesseract` program are both installed.

## Workflow

```bash
python -m audit_tool new bank-2026 --title "Account restriction" --institution "Example Bank"
python -m audit_tool ingest bank-2026 bounce.eml --source "Microsoft 365"
python -m audit_tool ingest bank-2026 letter.txt call.txt statement.csv screenshot.png
python -m audit_tool show   bank-2026 EVT-0002
python -m audit_tool edit   bank-2026 EVT-0002 --set automated=yes --set "appeal_path=" --reason "read letter"
python -m audit_tool check  bank-2026
python -m audit_tool verify bank-2026
python -m audit_tool report bank-2026 --out bank-2026.md      # or --format json
```

Run `pip install -e .` to get a shorter `audit ...` command.

## What it ingests

| Input | How it's handled |
|---|---|
| `.eml` emails and bounce notices | Headers, SMTP codes (`550 5.7.193`), reason, automation signs |
| Letters (`.txt`) | Decision, reason, cited policy (`Section 12.3…`), date, appeal language |
| Call transcripts and chat logs (`.txt`) | Same as letters. Customer lines are never read as institution statements |
| Transaction CSVs | One event per row that isn't a plain success (declined, held, reversed…) |
| Screenshots (`.png`, `.jpg`, …) | OCR, then the same analysis as text. Dark-mode captures are inverted first. Microsoft 365 bounce screenshots yield code, rule sentence, sender, recipient, date and subject |
| PDF letters | The PDF's text layer. Scanned pages with no text layer are rendered and OCR'd |

Anything the tool extracts automatically is marked **extracted, unconfirmed** until a person sets it with `edit`.

For screenshots and PDFs, the recovered text is saved next to the original as `<file>.extracted.txt`. It is hashed and linked to the event, and the event notes record the method and mean OCR confidence. OCR sometimes drops spaces (`October2,2026`), so check names, dates and amounts against the image. Useful commands:

```bash
python -m audit_tool extract screenshot.png      # preview the extracted text without ingesting
python -m audit_tool ingest case-id scan.pdf --no-ocr   # store the file only
```

## Audit checks (per adverse decision)

| Rule | Question |
|---|---|
| AUTO | Was the decision automatic? |
| HUMAN | Was a human involved? |
| RULE | What rule triggered it? |
| EVIDENCE | What evidence supported the rule? |
| NOTICE | Was notice provided? |
| APPEAL | Was an appeal path disclosed? |
| REPRO | Is the decision reproducible from the reason given? |
| LAW | Does policy or law permit the action? |
| PROOF | Is the event itself documented by us? |

The gate is **PASS** only when a decision has a reason, a cited rule or code, and supporting evidence. Anything less gets an **AUDIT FLAG**.

## Integrity

- Evidence files are copied byte for byte into `cases/<id>/evidence/` and identified by SHA-256.
- `ledger.jsonl` is append-only and hash-chained. Corrections are added as new entries, so the history stays visible.
- `verify` reports any edited ledger line or any changed or missing evidence file.

## Limits

Findings describe what is missing from the *collected record*, not what happened inside the institution. Text extraction is pattern-based, so review each event. This is not legal advice.
