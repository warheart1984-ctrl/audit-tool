# Audit tool

[![tests](https://github.com/warheart1984-ctrl/audit-tool/actions/workflows/tests.yml/badge.svg)](https://github.com/warheart1984-ctrl/audit-tool/actions/workflows/tests.yml)

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

- Evidence files are copied byte for byte into `cases/<id>/evidence/` and identified by SHA-256. A file is stored only when it produces an event to link it to.
- `ledger.jsonl` is append-only and hash-chained. Corrections are added as new entries, so the history stays visible.
- `verify` reports:
  - edited, deleted or unreadable ledger lines;
  - entries that refer to events that don't exist;
  - evidence files that changed or went missing;
  - files or symbolic links in `evidence/` that the ledger doesn't list;
  - malformed entries, which are skipped and listed instead of crashing the tool;
  - fields on a ledger line that the hash doesn't cover, so nothing can ride along uncommitted;
  - "confirmed" claimed when an event is created. Only an edit (`audit edit`, with a reason) confirms a fact.
- Appends take a lock file, so two processes writing to one case can't lose or interleave entries.
- Case IDs must be plain names: letters, digits, `.`, `_` and `-`, starting and ending with a letter or digit, with no `..` and no Windows device names such as `CON`. A case can never be read or written outside the `cases/` folder, and two IDs can't name the same folder.
- Extraction runs on documents the audited party wrote, so extracted values are not trusted to clear findings: a document claiming "manually reviewed" or "appeal to the ombudsman" produces a *claimed, unconfirmed* finding instead of silence, and only a field confirmed by a person (`audit edit`) clears it or satisfies the PASS gate.

### What the hash chain does *not* prove

Someone with write access to the case folder can replace the whole ledger with a new chain that is internally consistent, and plain `verify` can't tell. The defence is the **ledger head**, the hash of the latest entry:

```bash
python -m audit_tool head bank-2026                    # also printed after every change
python -m audit_tool verify bank-2026 --expect <hash>  # fails if that hash is no longer in the ledger
```

Save the head somewhere off this machine after key steps. You could email it to yourself or to the other party, or include it in a complaint. Entries are only ever appended, so a saved head stays valid as the case grows. If the history before it is ever rewritten, `--expect` fails. Each report also prints the current head.

Two things an anchored head still does *not* prove:

- **Anything appended after it.** `verify --expect` says how many entries follow the anchor and that they are not covered by it — review them and save the new head. An anchor also can't notice entries *deleted* from the tail after it, so re-anchor after every session.
- **Who wrote an entry.** For that, entries need signatures.

### Signing entries

Give the tool a signing key and every new entry records an `actor` and an HMAC-SHA256 `sig` over its hash:

```bash
python -m audit_tool keygen ~/audit-signing.key   # keep it OUTSIDE the cases folder and out of git
python -m audit_tool --key-file ~/audit-signing.key --actor alex ingest bank-2026 letter.pdf
python -m audit_tool --key-file ~/audit-signing.key verify bank-2026
```

Or set `AUDIT_KEY_FILE` and `AUDIT_ACTOR`. With a key, `verify` flags:
- entries appended without the key after signing began;
- entries signed by a different key;
- a ledger with no signed entries at all.

Unsigned history from before signing began is allowed and reported as such. That also means stripping the signatures from the *earliest* entries isn't flagged. Their content stays protected, because the signed entries after them commit to it through the chain.

Whoever holds the key is trusted. A signature proves *key possession*, nothing more. Signing is opt-in: an unsigned ledger has no record of authorship, so someone with write access can append an event and an "edit" confirming it, and plain `verify` won't notice.

### Limits on untrusted files

Evidence may come from the party being audited, so each file's cost is bounded:
- Text and email files over 20 MB are stored but not parsed.
- CSVs are read up to 100,000 rows.
- PDFs are read up to 500 pages, and at most 25 scanned pages are OCR'd.
- Images over 50 megapixels are not OCR'd.

The limits are constants at the top of `ingest.py` and `extract.py`. Report text from evidence is escaped, so a document can't inject headings, links or fake findings into the case file.

## Tests

```bash
pip install -e ".[ocr,dev]"
python -m pytest
```

## Limits

Findings describe what is missing from the *collected record*, not what happened inside the institution. Text extraction is pattern-based, so review each event. Extracted labels, such as which mail system bounced a message, can be spoofed by whoever wrote the document. That's why they stay *unconfirmed* until you check them. This is not legal advice.

## License

MIT. See [LICENSE](LICENSE).
