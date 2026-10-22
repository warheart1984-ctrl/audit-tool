# Handoff: audit-tool

Hi Steven. This note gets you productive quickly. The [README](README.md) has the full user-facing detail.

## What it is

A command-line tool that turns evidence about automated decisions into an audit case file. The evidence can be bounce emails, denial letters, call transcripts, bank CSVs, screenshots or PDFs. Each case file says what the record shows and what it lacks: no human review, no cited rule, no supporting evidence, no appeal path. Python 3.11+. The core has no dependencies; OCR and PDF support are optional extras.

## How it works

```
file ─► ingest.py / extract.py ─► Event (fields marked "extracted")
                                     │
                         audit edit  ▼  (person confirms or corrects; fields marked "confirmed")
                                     │
ledger.jsonl ◄── store.py ◄──────────┘   append-only, hash-chained, optionally signed
     │
     └─► replay ─► rules.py (findings + PASS/AUDIT FLAG gate) ─► report.py (Markdown / JSON)
```

| Module | Role |
|---|---|
| `models.py` | `Event` fields, editable-field allowlist, value validation |
| `ingest.py` | Detects the file type, then extracts facts with regexes: SMTP codes, decision words, reasons, policies, appeal language, labelled fields such as `Sender Address:`, dates |
| `extract.py` | Text from images (RapidOCR, with Tesseract as fallback) and PDFs (text layer first, then OCR for scanned pages), run in an isolated child process with a time limit |
| `ledger.py` | Hash chain, `seq:hash` anchors, Ed25519 signing, append lock, parse cache |
| `store.py` | Case folders, evidence copies (never through links), replay of the ledger into current state, `verify()` |
| `secure.py` | Owner-only permissions: `0700`/`0600` on Linux and macOS, owner-only ACLs on Windows |
| `rules.py` | The auditor questions. Only **confirmed** values clear a finding |
| `report.py` | Renders the case file. All evidence text is escaped |
| `cli.py` | `audit new / ingest / extract / show / edit / add / attach / check / verify / head / keygen / secure / report / list` |

The trust model is the design's core, so keep it intact:

1. Evidence is untrusted, because the audited party writes it.
2. Extraction only proposes values.
3. Only a person's `edit` confirms a value.
4. Only confirmed values clear findings.

## What's been hardened

Three outside security reviews were done. Every confirmed finding was fixed with regression tests.

- **Workspace confinement:** case IDs are confined to `cases/`. They reject traversal and absolute paths, a trailing `.`, and Windows device names.
- **Ledger integrity:**
  - Edits, deletions, unreadable lines and fields outside the hash are all detected.
  - `verify --expect <seq>:<hash>` detects a full ledger rewrite and counts the entries added after the anchor. With `--exact`, deletions from the end are caught too.
  - With an Ed25519 key, entries carry an author, a key id and a signature. Appends made without the key are flagged, and so is a signature removed while its `kid` remains. Every command checks signatures with the case's `signing-key.pub` by default and fails closed if it's missing. The public key verifies but can't forge, so it can be handed to the other side.
  - Confirmation can't be claimed when an event is created, only through an edit.
- **Replay:** malformed or orphaned entries are skipped and reported, never crashed on. IDs are never reused.
- **Concurrency:** a lock file around appends. Without it, Windows lost about 8% of entries under 4 parallel writers.
- **Evidence folder:** must match the ledger exactly. Unlisted files, symlinks and recorded paths that escape the folder are all flagged.
- **Read commands fail closed:** `check` and `show` refuse to run on a ledger that doesn't verify. `report` marks the report unreliable and exits 2.
- **Reports:** a document can't inject headings, links or fake findings.
- **Case data on disk:** owner-only permissions. `audit secure <case>` tightens older cases. No in-tool encryption; use full-disk encryption.
- **Untrusted files:**
  - Size limits on every parsed file type, plus caps on CSV rows, PDF pages, OCR pages and image pixels.
  - PDF and image decoding runs in a separate process with a time limit, away from the signing key.
  - Malformed CSV rows and a missing status column give warnings, and every warning is saved with the event.
  - A file with no adverse rows is kept on record.
- **Extraction can't clear findings:** a letter written to hit every pattern ("manually reviewed", "appeal to the ombudsman") still produces findings.
- **Dependencies:** minimum versions at known security fixes (Pillow 13, pypdf 6) and no upper limits, so security releases are never blocked.

## Known limits (by design, documented)

- **Signing is opt-in.** An unsigned ledger has no record of authorship. Someone with write access can append an event plus an edit confirming it.
- **An anchor only covers what existed when it was saved.** `--exact` catches later additions and deletions, but only against the newest anchor you hold, so save a new one after each session.
- **The private-key holder is trusted.** A signature proves possession of the key, nothing more. The `signing-key.pub` copy in a case folder is only as good as the key id the owner shared separately.
- **Isolation isn't a sandbox.** The extraction process runs as the same OS user.
- **Extraction is pattern-based** and tuned on Microsoft 365 bounces and simple letters. OCR on phone screenshots drops spaces, so the parser tolerates that, but confirmation is still required.
- **Slash dates** are read month/day, and bounce timestamps carry no time zone.

## Running it

```bash
pip install -e ".[ocr,sign,dev]"
python -m pytest                     # 145 tests; platform-specific tests skip where they don't apply
python tools/mutation/run.py         # mutation run: plants 52 known defects, checks each is caught (~20 min)
python tests/make_fixtures.py        # regenerates OCR/PDF sample files into tests/fixtures/ (git-ignored)
```

CI (`.github/workflows/tests.yml`) runs the suite on Linux and Windows with Python 3.11 and 3.12 on every push and PR. The `mutation` workflow runs the mutation harness on both platforms when triggered by hand from the Actions tab.

## House rules

- **Never commit real evidence.** `cases/` and image, PDF and `.eml` files in the repo root are git-ignored. The owner's real case files are kept locally and are not in this repo.
- **Keep private keys out of the repo.** `keygen` refuses to write a key inside `cases/`.
- **Every security fix needs a test** that fails on the old code.
- **Don't change the ledger format casually.** It's specified in `docs/LEDGER_FORMAT.md`, and `tests/test_known_answers.py` pins it to values computed with `sha256sum`, OpenSSL and RFC 8032. If a known-answer test fails, you broke compatibility with every independent verifier. Don't "fix" the expected values; recompute them outside the tool, and only for a deliberate, versioned format change.
- **Every guarantee needs a mutant.** Add one to `tools/mutation/mutants.py` and check it's killed. A green suite isn't proof on its own: the first mutation run found 7 guarantees no test enforced, now covered in `tests/test_blind_spots.py`.

## Reasonable next steps

- Support Outlook `.msg` files and HTML-only emails.
- Let the user set the date order and time zone per case.
- Add a PDF export of the report, for complaints and filings.
- Extend extraction to more bounce formats (Gmail, Exchange on-prem) and bank letter styles, with tests built from synthetic samples.
