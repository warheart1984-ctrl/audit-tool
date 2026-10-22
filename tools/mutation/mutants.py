"""Planted defects, each targeting one guarantee the README claims.

Each mutant is (id, file in audit_tool/, exact original text, replacement,
guarantee broken). For a defect that needs several coordinated edits, the third
field is a list of (original, replacement) pairs and the fourth is None.
Every original text must occur exactly once in the file; the
runner refuses to run a mutant that doesn't apply, so it can't "survive" by
never having been planted. When you change guarded code, update its mutant.
When you add a guarantee, add a mutant for it.
"""

# Mutants that can only be caught on one platform (their tests skip elsewhere).
PLATFORM_ONLY = {"Z1": "win32", "Z2": "posix"}

MUTANTS = [
    # ledger.py: chain, hash coverage, signatures, anchors, locking
    ("L1", "ledger.py", 'if entry.get("prev") != prev:', "if False:", "chain link check"),
    ("L2", "ledger.py", 'intact = _entry_hash(entry) == entry.get("hash")', "intact = True", "entry hash check"),
    ("L3", "ledger.py", "extra = entry.keys() - REQUIRED_KEYS - OPTIONAL_KEYS", "extra = set()", "unhashed fields flagged (T2)"),
    ("L4", "ledger.py", "                if signing_started:\n", "                if False:\n", "unsigned append after signing flagged"),
    ("L5", "ledger.py", 'if entry.get("kid") != self.kid:', "if False:", "foreign-key signature flagged"),
    ("L6", "ledger.py", "if entries and not signing_started:", "if False:", "nothing-signed flagged"),
    ("L7", "ledger.py", "            body[k] = entry[k]", "            pass", "actor/kid covered by hash"),
    ("L8", "ledger.py", 'entries[seq - 1].get("hash") == digest', "True", "anchor position check"),
    ("L9", "ledger.py", "fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)",
     "fd = os.open(lock, os.O_CREAT | os.O_WRONLY, 0o600)", "append lock is exclusive"),
    ("L10", "ledger.py", "except (InvalidSignature, ValueError):\n                problems.append",
     "except (InvalidSignature, ValueError):\n                pass\n            if False:\n                problems.append",
     "invalid signature flagged"),
    ("L11", "ledger.py", 'if "kid" in entry and "sig" not in entry:', "if False:",
     "removed signature caught by its leftover kid (PR #1)"),
    ("U1", "ledger.py", "                    except UnicodeEncodeError:\n",
     "                    except ZeroDivisionError:\n", "lone surrogate is an integrity failure, not a crash (PR #1)"),
    ("U2", "ledger.py", "        except UnicodeDecodeError as exc:", "        except ZeroDivisionError as exc:",
     "invalid UTF-8 is an integrity failure, not a crash"),
    ("U3", "cli.py", 'print(f"INTEGRITY FAILED: {exc}", file=sys.stderr)\n        sys.exit(2)',
     'print(f"INTEGRITY FAILED: {exc}", file=sys.stderr)\n        sys.exit(1)', "unreadable ledger exits 2"),
    # store.py: replay, case ids, evidence folder
    ("S1", "store.py", 'p["origin"] = {k: v for k, v in origin.items() if v == "extracted"}', 'p["origin"] = origin',
     "confirmation can't be claimed at creation (T5)"),
    ("S2", "store.py", "if name not in EDITABLE:", "if False:", "non-editable fields rejected in replay"),
    ("S3", "store.py", 'if p["id"] in events:', "if False:", "duplicate event id ignored"),
    ("S4", "store.py", 'and ".." not in case_id', "", "case id rejects '..'"),
    ("S5", "store.py", "if resolved.parent != root or resolved.name != case_id:", "if False:", "case folder confined to workspace"),
    ("S6", "store.py", "elif path.is_file() and rel not in recorded:", "elif False:", "unrecorded evidence files flagged"),
    ("S7", "store.py", 'elif sha256_file(path) != art["sha256"]:', "elif False:", "changed evidence files flagged"),
    ("S8", "store.py", "if self.evidence_dir.is_symlink() or (self.evidence_dir.exists() and self.evidence_dir.resolve() != expected):",
     "if False:", "evidence never written through a link/junction"),
    ("S9", "store.py", "elif exact and after:", "elif False:", "--exact catches later entries"),
    ("S10", "store.py", "if bad := _event_payload_problem(p):", "if False:", "malformed event.add rejected (T3)"),
    ("S11", "store.py", "if not path.resolve().is_relative_to(case_root) or not rel.startswith(\"evidence/\"):",
     "if False:", "recorded paths can't escape evidence/"),
    ("K1", "store.py", "elif (directory / PUBLIC_KEY_FILE).exists():", "elif False:",
     "every command checks signatures with the case's public key (PR #1)"),
    ("K2", "store.py", "if self.ledger.verify_key is None and self.ledger.is_signed():\n            # Fail closed",
     "if False:\n            # Fail closed", "signed case without a usable public key fails closed"),
    ("K3", "store.py", "if self.ledger.signer is None and self.ledger.is_signed():", "if False:",
     "no unsigned writes to a signed case"),
    # rules.py: the trust boundary (T4) and the gate
    ("R1", "rules.py", 'return bool(getattr(ev, name)) and ev.origin.get(name) == "confirmed"',
     "return bool(getattr(ev, name))", "extracted text can't clear findings (T4)"),
    ("R2", "rules.py", ' and has_rule else "AUDIT FLAG"', ' else "AUDIT FLAG"', "PASS gate needs a confirmed rule"),
    ("R3", "rules.py", 'elif ev.human_involved != "yes":', "elif False:", "HUMAN finding when no review"),
    ("R5", "rules.py", 'elif not ev.appeal_path:', "elif False:", "APPEAL finding when none disclosed"),
    ("R6", "rules.py", 'if ev.reproducible == "no" or (ev.reproducible == "unknown" and not ev.reason):', "if False:",
     "REPRO finding"),
    # report.py: escaping
    ("P1", "report.py", 'return _MD_SPECIAL.sub(r"\\\\\\1", " ".join(str(text or "").split()))',
     'return " ".join(str(text or "").split())', "evidence text escaped in reports"),
    ("P2", "report.py", "fence = \"`\" * max(3, longest + 1)", "fence = \"```\"", "fence longer than evidence backticks"),
    ("P3", "report.py", "    if problems:\n        lines += [\"> **WARNING: INTEGRITY FAILED.**",
     "    if False:\n        lines += [\"> **WARNING: INTEGRITY FAILED.**", "report banner on failed integrity"),
    # cli.py: fail closed
    ("C1", "cli.py", 'if problems and not getattr(a, "unverified", False):', "if False:", "check/show refuse forged ledgers"),
    ("C2", "cli.py", "the report is marked as unreliable.\", file=sys.stderr)\n        sys.exit(2)",
     "the report is marked as unreliable.\", file=sys.stderr)", "report exits 2 on failed integrity"),
    ("C3", "cli.py", "            case.record_artifact(artifact, note)\n", "", "no-adverse files kept on record"),
    # ingest.py: parsing limits and customer lines
    ("I1", "ingest.py", "if not CUSTOMER_LINE.match(appeal.group(0)):", "if True:", "customer lines aren't appeal paths"),
    ("I2", "ingest.py", "if limit is not None and size > limit:", "if False:", "byte limits per file type"),
    ("I3", "ingest.py", "            if i - 1 > MAX_CSV_ROWS:", "            if False:", "CSV row cap"),
    ("I4", "ingest.py", "        ev[\"notes\"] = f\"{ev['notes']} {note}\" if ev.get(\"notes\") else note",
     "        pass", "warnings saved with events"),
    ("I5", "ingest.py", "            except csv.Error as exc:", "            except ZeroDivisionError as exc:", "bad CSV rows don't crash"),
    # extract.py: isolation
    ("X1", "extract.py", "hidden = {k: os.environ.pop(k) for k in SENSITIVE_ENV if k in os.environ}", "hidden = {}",
     "key path hidden from extractor"),
    ("X2", "extract.py", "        if img.width * img.height > MAX_IMAGE_PIXELS:", "        if False:", "image pixel cap"),
    ("X3", "extract.py", "        if i >= MAX_PDF_PAGES:", "        if False:", "PDF page cap"),
    # Ledger FORMAT: self-consistent changes. The tool still agrees with itself,
    # so only tests against values computed outside the tool can catch these.
    # Each would silently break anyone verifying a ledger independently.
    ("F1", "ledger.py", 'separators=(",", ":"))', "separators=None)", "canonical JSON: compact separators"),
    ("F2", "ledger.py", "sort_keys=True, ensure_ascii=False,", "sort_keys=True, ensure_ascii=True,",
     "canonical JSON: UTF-8, not \\u escapes"),
    ("F3", "ledger.py", "json.dumps(body, sort_keys=True,", "json.dumps(body, sort_keys=False,", "canonical JSON: sorted keys"),
    ("F4", "ledger.py", 'hashlib.sha256(raw.encode("utf-8"))', 'hashlib.sha3_256(raw.encode("utf-8"))',
     "entry hash is SHA-256"),
    ("F5", "ledger.py",
     [('self.signer.sign(entry["hash"].encode("ascii"))', 'self.signer.sign(bytes.fromhex(entry["hash"]))'),
      ('str(entry.get("hash")).encode("ascii"))', 'bytes.fromhex(str(entry.get("hash"))))')],
     None, "signature covers the ASCII hex hash"),
    ("F6", "ledger.py", "hexdigest()[:16]", "hexdigest()[:12]", "key id is the first 16 hex of SHA-256(public key)"),
    ("F7", "ledger.py", 'GENESIS = "0" * 64', 'GENESIS = "f" * 64', "chain starts from 64 zeros"),
    # secure.py: permissions
    ("Z1", "secure.py", '"/inheritance:r",\n             "/grant:r"', '"/grant:r"', "Windows: inherited access removed"),
    ("Z2", "secure.py", "    os.chmod(path, 0o700)\n\n\ndef restrict_file", "    pass\n\n\ndef restrict_file", "POSIX: folders 0700"),
]
