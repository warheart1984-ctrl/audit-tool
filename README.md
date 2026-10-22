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

- Evidence files are copied byte for byte into `cases/<id>/evidence/` and identified by SHA-256. A file that produces no event, such as a statement with nothing adverse in it, is still stored and recorded as "checked, nothing adverse", with any ingest warnings. Warnings that limited an extraction are also saved with the event, not just printed.
- `ledger.jsonl` is append-only and hash-chained. Corrections are added as new entries, so the history stays visible.
- `verify` reports:
  - edited, deleted or unreadable ledger lines;
  - entries that refer to events that don't exist;
  - evidence files that changed or went missing;
  - files or symbolic links in `evidence/` that the ledger doesn't list;
  - an `evidence/` folder that is itself a link or junction;
  - malformed entries, which are skipped and listed instead of crashing the tool;
  - fields on a ledger line that the hash doesn't cover, so nothing can ride along uncommitted;
  - "confirmed" claimed when an event is created. Only an edit (`audit edit`, with a reason) confirms a fact.
- **Read commands fail closed.** `check` and `show` refuse to run on a ledger that doesn't verify unless you pass `--unverified`. `report` still writes the file, with a warning at the very top, and exits with code 2. `list` marks such cases INTEGRITY FAILED.
- Evidence is written only into a real `evidence/` folder inside the case, never through a link or junction, and existing files are never overwritten or followed.
- Appends take a lock file, so two processes writing to one case can't lose or interleave entries.
- Case IDs must be plain names: letters, digits, `.`, `_` and `-`, starting and ending with a letter or digit, with no `..` and no Windows device names such as `CON`. A case can never be read or written outside the `cases/` folder, and two IDs can't name the same folder.
- Extraction runs on documents the audited party wrote, so extracted values are not trusted to clear findings. A document claiming "manually reviewed" or "appeal to the ombudsman" produces a *claimed, unconfirmed* finding instead of silence. Only a field confirmed by a person (`audit edit`) clears a finding or satisfies the PASS gate.

### Anchors: proving the ledger wasn't rewritten

Someone with write access to the case folder can replace the whole ledger with a new chain that is internally consistent, and plain `verify` can't tell. The defence is an **anchor**, `<seq>:<hash>` of the latest entry, saved somewhere off this machine:

```bash
python -m audit_tool head bank-2026                               # also printed after every change
python -m audit_tool verify bank-2026 --expect 12:3f9a...         # history up to entry 12 is unchanged
python -m audit_tool verify bank-2026 --expect 12:3f9a... --exact # ...and nothing was added or removed after it
```

You could email the anchor to yourself or to the other party, or include it in a complaint. Without `--exact`, `verify` also tells you how many entries were added after the anchor. Those entries aren't covered by it, so review them and save the new anchor. With `--exact`, any entry added *or deleted* after the anchor fails verification. That catches someone truncating the end of the ledger, provided the anchor you hold is the latest one. So save a new anchor whenever you finish working on a case. Each report prints the anchor it was made from.

### Signing entries (Ed25519)

An anchor proves the history wasn't changed. It doesn't show *who* wrote an entry. For that, sign entries with an Ed25519 key pair (`pip install -e ".[sign]"`):

```bash
python -m audit_tool keygen ~/audit-signing.key        # writes the private key and ~/audit-signing.key.pub
python -m audit_tool --key-file ~/audit-signing.key --actor alex ingest bank-2026 letter.pdf
python -m audit_tool --key-file ~/audit-signing.key verify bank-2026
python -m audit_tool --public-key audit-signing.key.pub verify bank-2026   # what the other side runs
```

Or set `AUDIT_KEY_FILE`, `AUDIT_PUBLIC_KEY` and `AUDIT_ACTOR`. Each new entry records an `actor`, the key id `kid` and a signature over its hash. Both `actor` and `kid` are covered by the hash.

- **Private key:** keep it outside the cases folder (`keygen` refuses otherwise) and out of git. It is written owner-only. Whoever holds it can sign as you.
- **Public key:** give it to a bank, a regulator or opposing counsel. It lets them check every signature but **not** forge one, unlike a shared-secret scheme. The case also ships a copy in `signing-key.pub`, which `verify` uses when no key is given. Anyone who can write the folder could swap that copy, so the key id it prints has to match the one you gave them separately.
- **What `verify` flags with a key:**
  - entries appended without the key after signing began;
  - entries signed by another key;
  - altered signatures;
  - a ledger with nothing signed.
- **Unsigned history** from before signing began is allowed and reported as such.

Signing is opt-in. An unsigned ledger has no record of authorship, so someone with write access can append an event and an "edit" confirming it, and plain `verify` won't notice.

### Protecting the data on this machine

Case folders hold bank letters, statements and IDs, so they are created owner-only:
- **Linux and macOS:** folders `0700`, files `0600`.
- **Windows:** inherited permissions (often `Authenticated Users: Modify` from the drive) are removed, and only your account and SYSTEM get access. Python 3.12.4+ also grants Administrators, who can take ownership of any file anyway.

For a case created before this existed, run:

```bash
python -m audit_tool secure bank-2026
```

`verify` warns on Linux and macOS when a case is readable by other accounts. The tool does **not** encrypt case files. For encryption at rest, use full-disk encryption (BitLocker, FileVault or LUKS). That protects the same data without complicating verification or key handling.

### Limits on untrusted files

Evidence may come from the party being audited, so each file's cost is bounded:
- **Size limits:** text and email files over 20 MB, CSVs over 50 MB, PDFs over 100 MB and images over 50 MB are stored but not parsed.
- **CSVs** are read up to 100,000 rows. A malformed row, such as one with a field over the CSV module's size limit, stops reading with a warning instead of crashing.
- **PDFs** are read up to 500 pages, and at most 25 scanned pages are OCR'd.
- **Images** over 50 megapixels are not OCR'd.
- **Isolated decoding:** PDF and image decoding (pypdf, pdfium, Pillow, RapidOCR) runs in a separate child process with a 5-minute time limit. A decoder bug can't read the signing key from the tool's memory, and a crash or hang can't take the tool down with it. The key file's path isn't passed to the child either. The child still runs as your OS user, so this isn't a full sandbox.

The limits are constants at the top of `ingest.py` and `extract.py`. Report text from evidence is escaped, so a document can't inject headings, links or fake findings into the case file.

## Tests

```bash
pip install -e ".[ocr,sign,dev]"
python -m pytest
```

## Limits

Findings describe what is missing from the *collected record*, not what happened inside the institution. Text extraction is pattern-based, so review each event. Extracted labels, such as which mail system bounced a message, can be spoofed by whoever wrote the document. That's why they stay *unconfirmed* until you check them. This is not legal advice.

## License

MIT. See [LICENSE](LICENSE).
