# Independent verification of the ledger at `6224642`

Clean-room checker: `independent/verify_ledger.py` (hashlib and Ed25519 from the `cryptography` library).
Corpus and comparison: `independent/build_corpus.py`, `independent/corpus/`.

No existing project file is modified.

## When implementation code was first read

The verifier was written from `docs/LEDGER_FORMAT.md` and the README's verify/anchor usage, then committed, before `audit_tool/` or `tests/` was opened. Its `--self-test` recomputes the spec's worked example (canonical bytes, SHA-256, key id, and the RFC 8032 test-1 signature).

Ledgers for the corpus were produced by the CLI. One verifier edit after that, and still before any source read, accepts `stored_path` and `sha256` on `payload.artifact` as well as on the payload. The format spec names those fields and does not give the JSON path (`docs/LEDGER_FORMAT.md` line 91).

**First read of implementation code: 2026-10-22T11:50:00Z**, after the corpus had already been compared.

## Agreement

20 runs. The two verifiers agree on 18. "Spec" is the pass/fail required by `docs/LEDGER_FORMAT.md`, not the extra README policy.

| Case | Run | Spec | Tool | Clean-room | Agree |
|---|---|---|---|---|---|
| `01-unsigned-unicode` | plain | pass | pass | pass | yes |
| `02-signed-unicode` | plain | pass | pass | pass | yes |
| `02-signed-unicode` | exact-anchor | pass | pass | pass | yes |
| `03-second-case` | plain | pass | pass | pass | yes |
| `04-edited-field` | plain | fail | fail | fail (`hash`) | yes |
| `05-swapped-middle` | plain | fail | fail | fail (`prev`) | yes |
| `06-truncated-tail` | plain | pass | pass | pass | yes |
| `06-truncated-tail` | expect-old-tip | fail | fail | fail (`anchor_missing`) | yes |
| `07-append-after-anchor` | plain | pass | pass | pass | yes |
| `07-append-after-anchor` | expect | pass | pass | pass | yes |
| `07-append-after-anchor` | exact | fail | fail | fail (`anchor_extended`) | yes |
| `08-stripped-earliest-sig` | plain | fail | pass | fail (`signature_incomplete`) | **no** |
| `09-wrong-kid` | plain | fail | fail | fail (`kid`) | yes |
| `10-reordered-keys` | plain | pass | pass | pass | yes |
| `11-u-escaped` | plain | pass | pass | pass | yes |
| `12-lone-surrogate` | plain | fail | fail | fail (`canonical`) | yes |
| `13-nonascii-sig` | plain | fail | fail | fail (`sig`) | yes |
| `14-replaced-genesis` | plain | pass | pass | pass | yes |
| `14-replaced-genesis` | expect-old-tip | fail | fail | fail (`anchor_hash`) | yes |
| `15-unsigned-with-key` | with-key | pass | fail | pass | **no** |

Real cases cover an unsigned Unicode title, a signed Unicode case (unsigned `case.create`, then signed ingest and edit), and a second unsigned case. Tamper definitions are in `build_corpus.py`.

Both accept reordered top-level keys and `\u` escapes. The hash is of the re-serialized object (`docs/LEDGER_FORMAT.md` lines 24–33), not of the raw line. Both reject an edited field, a middle swap whose own hashes were recomputed but whose neighbours still point at the old hashes, a truncated tip under the old anchor, a replaced genesis under the old anchor, a wrong `kid` after the chain was recomputed and re-signed, a non-ASCII signature, and a lone surrogate. An append after the anchor passes `verify --expect` and fails `verify --expect --exact`.

## Disagreements

### 1. Stripping the earliest signature — the tool is wrong

`08-stripped-earliest-sig` deletes the `sig` field of the first signed entry and leaves `kid`, `actor`, and `hash` untouched. The clean-room verifier fails with `signature_incomplete`. The tool exits 0. With the resulting tip as `--expect` and `--exact`, the tool still exits 0: the anchor matches, because `sig` is not in the hash.

The tool then reports that entries 1–2 "predate signing" and that every entry from 3 on is signed. Entry 2 still has `kid`.

Why this is not caught by the chain:

- The hash covers `actor` and `kid` and leaves out `sig` (`docs/LEDGER_FORMAT.md` lines 24–25 and 38; `audit_tool/ledger.py` lines 44–50).
- Deleting `sig` does not change `hash`, `prev`, or an anchor.

`_verify_signatures` treats "no `sig`" as unsigned and does not look at `kid` (`audit_tool/ledger.py` lines 299–304). Signing is considered started only once a `sig` key is present (line 305). Stripping the earliest signature widens the unsigned prefix. Stripping a later signature is rejected (`unsigned entry after signing began`). Stripping every signature is rejected when a key is supplied (`no entry is signed with this key`, lines 313–314). The hole is specifically the earliest signature, while a later one remains.

The format spec says `kid` is the signing key id present on signed entries and `sig` is that signature (lines 17–19), and that unsigned entries are allowed only before the first signed one (line 40). It never says a `kid` with no `sig` is unsigned history. Because `sig` is outside the hash, the only way to keep a signature from being deleted without breaking an anchor is to reject a `kid` that has no valid `sig`. The clean-room verifier does that. The tool does not.

`tests/test_signing.py` `test_strip_all_signatures_is_flagged` removes `sig`, `kid`, and `actor` together, which breaks the hash. It does not cover this edit.

### 2. Unsigned ledger checked with a public key — the format spec is incomplete

`15-unsigned-with-key` is a valid unsigned ledger. The clean-room verifier passes. The tool exits 2: `no entry is signed with this key`.

`docs/LEDGER_FORMAT.md` line 40 allows unsigned entries before the first signed one. A ledger with no signed entry satisfies that. The README does require this failure when a key is supplied (README lines 119–124), and `audit_tool/ledger.py` lines 313–314 implement it.

The tool matches the README. The clean-room verifier matches the format spec. The format spec does not describe this verify-with-a-key policy. That is a spec gap, not a chain bug. The verifier was left on the format-spec side so the gap stays visible.

## Blue-team re-check

| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | `check`, `show`, and `report` refuse a broken ledger and exit nonzero | **partial** | Hash breaks are refused. On `04-edited-field`, `check` and `show` exit 2 and do not print the event; `report` exits 2 and puts `WARNING: INTEGRITY FAILED` above the summary (`audit_tool/cli.py` lines 32–44, 149–172, 251–262; `audit_tool/report.py` lines 67–70). A forged signature is not refused: on `13-nonascii-sig`, `verify` exits 2, while `check`, `show`, and `report` exit 0. Only `verify` loads `signing-key.pub` (`audit_tool/cli.py` lines 178–184). |
| 2 | Tail truncation, a replaced ledger, and appends after the anchor fail `verify --expect` | **partial** | Truncation of the saved tip fails `--expect` (`06`, `anchor_missing`; `audit_tool/store.py` lines 292–296). A recomputed replacement fails `--expect` (`14`, `anchor_hash`). An append does **not** fail `--expect`; both verifiers pass and the tool only notes the extra entry. `--exact` fails it (`07`; `audit_tool/store.py` lines 297–299; `tests/test_cli_signing.py` lines 55–62). That matches `docs/LEDGER_FORMAT.md` lines 42–44. It does not match a reading where the append itself fails `--expect`. |
| 3 | Signing is asymmetric, and stripping the earliest sig is rejected | **partial** | Ed25519 is real: the public key verifies, a wrong `kid` fails even after a valid re-signature (`09`; `audit_tool/ledger.py` lines 306–312), and an altered signature fails `verify` (`13`). Stripping the earliest `sig` is not rejected. See disagreement 1. The same file still passes `--expect --exact`. |
| 4 | Case file permissions and encryption | **fixed** | New case trees are `0700`/`0600` (`audit_tool/secure.py` lines 38–57; `tests/test_hardening.py`). `verify` warns when other accounts can read, and `audit secure` tightens an old tree. Encryption is explicitly out of scope: full-disk encryption is the documented control (`audit_tool/secure.py` lines 11–12, README lines 128–140). |
| 5 | Pillow pin and CVEs | **fixed** | `Pillow>=13.0.0` with no upper bound (`pyproject.toml` lines 14–22). Pillow 13.0.0 (2026-10-16) is the release that fixes the JPEG/TIFF decoder issues through 12.3.0, including the JPEG draft-mode overflow and the in-memory TIFF use-after-free. No later Pillow release was listed. |
| 6 | PDF/CSV byte caps, parser sandboxing, and the pypdf floor | **partial** | Caps are in code and tests: text 20 MB, CSV 50 MB / 100,000 rows, PDF 100 MB / 500 pages / 25 OCR pages, images 50 MB / 50 megapixels (`audit_tool/ingest.py` lines 28–32 and 364–366, `audit_tool/extract.py` lines 25–28). Decoding runs in a spawned child with a 300s limit, and `AUDIT_KEY_FILE` is removed from that child's environment (`audit_tool/extract.py` lines 179–217). The child is still the same OS user; the code says this is not a sandbox. `pypdf>=6.0.0` does fix CVE-2025-55197. It does not force the later fixes. 6.21.2 (2026-10-21) is current; 6.20–6.21 fix further memory and parser bugs, including CVE-2026-113786 (fixed in 6.21.1), where `/DCTDecode` data could be handed to the wrong Pillow parser. |
| M | Symlinks | **fixed** | A linked `evidence/` directory is refused before a write (`audit_tool/store.py` lines 178–184). Verify flags a linked evidence file and an unlisted link (`store.py` lines 307–334). `tests/test_store.py` and `tests/test_hardening.py` cover this. |
| M | Extraction warnings in the ledger | **fixed** | Warnings are appended to the event `notes` before the event is written (`audit_tool/ingest.py` lines 416–421). `tests/test_hardening.py` `test_ingest_warnings_are_saved_with_the_event` reads them back with `show`. |
| M | CSV hash recording | **fixed** | Every ingested file is copied and recorded with its SHA-256 (`audit_tool/store.py` `store_artifact`, lines 206–224), including a CSV with no adverse rows (`artifact.record`; `tests/test_cli.py`). |
| M | Timestamps and finding ids | **fixed** | Dates extracted from text are normalized to ISO (`audit_tool/ingest.py` `normalize_date`; `tests/test_ingest.py` maps a squashed bounce timestamp to `2026-10-21T21:38:40`). Ledger entry times are UTC. Finding ids are `AF-NNNN` in `(timestamp, event id)` order (`audit_tool/rules.py` lines 117–122), so they do not depend on dict order. They are positional: adding an earlier event renumbers later ids. |
| M | Surrogate crash | **partial** | A lone `\uD800` in `12-lone-surrogate` makes the tool exit 1 with `error: 'utf-8' codec can't encode character '\ud800'`, and there is no traceback. `UnicodeEncodeError` is a `ValueError`, so `audit_tool/cli.py` lines 379–381 catch it. `_entry_hash` still lets `str.encode("utf-8")` raise (`ledger.py` line 50) instead of recording an integrity problem, and the exit code is 1 rather than 2. `audit list` stops at that case (11 cases printed, then the codec error). The clean-room verifier reports `canonical` and exits 1 without aborting the process. |

## New issues

1. **High — the earliest signature can be removed without touching the anchor.** Disagreement 1. Write access to `ledger.jsonl` is enough. `verify`, `verify --expect`, and `verify --expect --exact` all succeed, and the tool describes the stripped entry as pre-signing history. Later signatures remain valid, so the log still looks partly signed.

2. **Medium — `check`, `show`, `report`, and `list` do not load `signing-key.pub`.** On `13-nonascii-sig`, `verify` exits 2 (`signature is invalid`). The same case exits 0 for `check`, `show`, and `report`, and the report does not carry the integrity warning. Content tampering is still refused (finding 1, case `04`). Authorship failures are not, unless the caller passed `--public-key` or `--key-file`. `list` has the same gap: a hash-valid, wrongly signed ledger is not marked `INTEGRITY FAILED`.

3. **Medium — the pypdf floor is 6.0.0.** That stops CVE-2025-55197 and, because there is no upper bound, does not block upgrades. A resolver that stays on 6.0.0 still accepts the parser bugs fixed through 6.21.2 (2026-10-21), including memory exhaustion and CVE-2026-113786. The byte caps and the child process limit the blast radius; they do not replace those fixes.

4. **Low — a lone surrogate aborts `verify` and `list` as a codec error.** Both verifiers reject the file, so this is not an integrity bypass. `list` does not finish the rest of the workspace, and the tool does not report the entry as a normal integrity failure.

The unsigned-with-a-key disagreement is not a product bug. It is the README rule that the format spec omits.
