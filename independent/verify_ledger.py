#!/usr/bin/env python3
"""Clean-room verifier for audit-tool ledger.jsonl.

Written only from docs/LEDGER_FORMAT.md and the verify/anchor usage in
README.md. This file does not import the audit tool. The implementation
under audit_tool/ and tests/ was not read while this verifier was written.
The one later edit, reading stored_path and sha256 from payload["artifact"]
as well as from the payload itself, came from ledger JSON the CLI produced,
still before that source was opened.

Checks, in the words of the format spec:

* one UTF-8 JSON object per line, and no field outside the listed set
* seq starts at 1 and counts with no gaps
* prev is 64 zero hex digits on entry 1, otherwise the previous hash
* hash is lowercase SHA-256 of the canonical covered object
* canonical JSON: keys sorted at every level, separators "," and ":"
  with no spaces, non-ASCII as raw UTF-8, no trailing newline
* Ed25519 (RFC 8032) over the 64 ASCII characters of hash
* kid is the first 16 hex characters of SHA-256 of the raw 32-byte key
* unsigned entries only before the first signed one
* an anchor ``seq:hash`` names an entry that still has that hash;
  ``--exact`` requires that entry to be the last one
* artifact stored_path files under evidence/ match sha256, and evidence/
  holds exactly those files

Spec readings that are easy to miss (see the report for citations):

* The hash is of a re-serialization, not of the raw line. Reordered keys
  and ``\\u`` escapes that decode to the same string still verify.
* ``sig`` is outside the hash, so deleting it does not change ``hash``
  or an anchor. An entry that still carries ``kid`` is a signed entry
  and must have a valid signature. A signature without ``kid`` is the
  same kind of incomplete signed entry.
* ``kid`` has to be the id of the public key the signature verifies
  under. A matching Ed25519 signature with a different ``kid`` fails.
* A lone UTF-16 surrogate cannot be written as the raw UTF-8 the
  canonical form requires, so the entry is rejected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

ALLOWED_FIELDS = frozenset(
    {"seq", "ts", "kind", "payload", "prev", "actor", "kid", "hash", "sig"}
)
REQUIRED_FIELDS = frozenset({"seq", "ts", "kind", "payload", "prev", "hash"})
KINDS = frozenset(
    {
        "case.create",
        "event.add",
        "event.update",
        "artifact.link",
        "artifact.record",
    }
)
ARTIFACT_KINDS = frozenset({"artifact.link", "artifact.record"})
GENESIS_PREV = "0" * 64
HEX64 = frozenset("0123456789abcdef")
MAX_DEPTH = 100

# Worked example from docs/LEDGER_FORMAT.md. Used only by --self-test.
_SPEC_ENTRY1 = (
    '{"kind":"case.create","payload":{"id":"kat","title":"Résumé — test"},'
    '"prev":"0000000000000000000000000000000000000000000000000000000000000000",'
    '"seq":1,"ts":"2026-10-22T00:00:00+00:00"}'
)
_SPEC_ENTRY1_HASH = "cb5d6982427a2469f5e726077a23382d7a127c1e5199fc9aeca69845dd2a4fde"
_SPEC_ENTRY2 = (
    '{"actor":"alex","kid":"21fe31dfa154a261","kind":"event.add",'
    '"payload":{"decision":"Denied","id":"EVT-0001"},'
    '"prev":"cb5d6982427a2469f5e726077a23382d7a127c1e5199fc9aeca69845dd2a4fde",'
    '"seq":2,"ts":"2026-10-22T00:00:01+00:00"}'
)
_SPEC_ENTRY2_HASH = "b040e15ba2e1a5fa4aba8e8c843d5a8aacf11d86085da5c106f9504acfcc7e3a"
_SPEC_ENTRY2_SIG = (
    "b827ffcf8421a131cae6000aa2785a7f6ea9404d1435b31b3fd9dbfdb78a4ae6"
    "e1e5aef8cebd8c3c33174b835cce2f97d0083cdc5c8fb1ca09423eceec3db40b"
)
_SPEC_PUB_HEX = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
_SPEC_KID = "21fe31dfa154a261"


class CanonicalError(ValueError):
    """The value cannot be serialized in the form the hash is defined over."""


class DuplicateKeyError(ValueError):
    """A JSON object repeats a key, so it is not one object."""


@dataclass(frozen=True)
class Finding:
    level: str
    code: str
    detail: str
    seq: int | None = None
    line: int | None = None


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    tip: str | None
    errors: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "entries": self.entries,
            "tip": self.tip,
            "errors": [asdict(item) for item in self.errors],
            "warnings": [asdict(item) for item in self.warnings],
        }


@dataclass(frozen=True)
class PublicKey:
    raw: bytes
    kid: str
    key: Ed25519PublicKey


def _is_lower_hex(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(char in HEX64 for char in value)


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError(key)
        obj[key] = value
    return obj


def canonical_bytes(value: Any, depth: int = 0) -> bytes:
    """Serialize ``value`` in the hash's canonical JSON form."""
    return _canonical_text(value, depth).encode("utf-8")


def _canonical_text(value: Any, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalError(f"JSON nested deeper than {MAX_DEPTH}")
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError("non-finite number")
        return json.dumps(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, list):
        inner = ",".join(_canonical_text(item, depth + 1) for item in value)
        return f"[{inner}]"
    if isinstance(value, dict):
        parts: list[str] = []
        for key in sorted(value):
            if not isinstance(key, str):
                raise CanonicalError("object key is not a string")
            encoded_key = _canonical_string(key)
            encoded_value = _canonical_text(value[key], depth + 1)
            parts.append(f"{encoded_key}:{encoded_value}")
        return "{" + ",".join(parts) + "}"
    raise CanonicalError(f"unsupported JSON value {type(value).__name__}")


def _canonical_string(text: str) -> str:
    out: list[str] = ['"']
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif char == "\b":
            out.append("\\b")
        elif char == "\f":
            out.append("\\f")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise CanonicalError("lone surrogate cannot be encoded as UTF-8")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def covered_object(entry: Mapping[str, Any]) -> dict[str, Any]:
    """Fields the hash covers. ``hash`` and ``sig`` are left out."""
    covered: dict[str, Any] = {
        "seq": entry["seq"],
        "ts": entry["ts"],
        "kind": entry["kind"],
        "payload": entry["payload"],
        "prev": entry["prev"],
    }
    if "actor" in entry:
        covered["actor"] = entry["actor"]
    if "kid" in entry:
        covered["kid"] = entry["kid"]
    return covered


def entry_hash(entry: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_bytes(covered_object(entry)))
    return digest.hexdigest()


def key_id(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return hashlib.sha256(raw_public_key).hexdigest()[:16]


def load_public_key(path: Path) -> PublicKey:
    data = path.read_bytes()
    raw = _public_key_bytes(data)
    return PublicKey(
        raw=raw,
        kid=key_id(raw),
        key=Ed25519PublicKey.from_public_bytes(raw),
    )


def public_key_from_raw(raw: bytes) -> PublicKey:
    return PublicKey(
        raw=raw,
        kid=key_id(raw),
        key=Ed25519PublicKey.from_public_bytes(raw),
    )


def _public_key_bytes(data: bytes) -> bytes:
    pem_at = data.find(b"-----BEGIN ")
    if pem_at != -1:
        end = data.find(b"-----END ", pem_at)
        if end == -1:
            raise ValueError("public key PEM is truncated")
        line_end = data.find(b"\n", end)
        block = data[pem_at:] if line_end == -1 else data[pem_at : line_end + 1]
        loaded = load_pem_public_key(block)
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        return loaded.public_bytes(Encoding.Raw, PublicFormat.Raw)
    stripped = b"".join(data.split())
    if stripped and all(chr(byte) in "0123456789abcdefABCDEF" for byte in stripped):
        if len(stripped) != 64:
            raise ValueError("hex public key must be 32 bytes")
        return bytes.fromhex(stripped.decode("ascii"))
    if len(data) == 32:
        return data
    raise ValueError("unrecognized public key format")


def signature_valid(public_key: PublicKey, hash_hex: str, sig_hex: str) -> bool:
    try:
        public_key.key.verify(bytes.fromhex(sig_hex), hash_hex.encode("ascii"))
    except InvalidSignature:
        return False
    return True


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    # ISO 8601 UTC, as in the spec's example. Fractional seconds are allowed.
    # A numeric offset of zero is UTC; Z is the same zone.
    if len(value) < 20:
        return False
    date, sep, rest = value[0:10], value[10:11], value[11:]
    if sep != "T" or date[4] != "-" or date[7] != "-":
        return False
    if not (date[:4] + date[5:7] + date[8:10]).isdigit():
        return False
    if len(rest) < 9 or rest[2] != ":" or rest[5] != ":":
        return False
    if not (rest[:2] + rest[3:5] + rest[6:8]).isdigit():
        return False
    tail = rest[8:]
    if tail.startswith("."):
        digits = tail[1:]
        zone = ""
        for index, char in enumerate(digits):
            if not char.isdigit():
                zone = digits[index:]
                digits = digits[:index]
                break
        else:
            zone = ""
        if not digits:
            return False
        tail = zone
    if tail not in {"Z", "+00:00", "+0000"}:
        return False
    year = int(date[0:4])
    month = int(date[5:7])
    day = int(date[8:10])
    hour = int(rest[0:2])
    minute = int(rest[3:5])
    second = int(rest[6:8])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        return False
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 60):
        return False
    if day > _days_in_month(year, month):
        return False
    return True


def _days_in_month(year: int, month: int) -> int:
    if month in {1, 3, 5, 7, 8, 10, 12}:
        return 31
    if month in {4, 6, 9, 11}:
        return 30
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    return 29 if leap else 28


def _parse_anchor(text: str) -> tuple[int, str]:
    seq_text, sep, hash_text = text.partition(":")
    if sep != ":" or not seq_text.isdigit() or not _is_lower_hex(hash_text, 64):
        raise ValueError("anchor must be <seq>:<64 lowercase hex>")
    seq = int(seq_text)
    # "01" and "1" must not be two names for the same entry.
    if seq_text != str(seq):
        raise ValueError("anchor seq must not have leading zeros")
    if seq < 1:
        raise ValueError("anchor seq must be 1 or greater")
    return seq, hash_text


def verify_ledger(
    ledger_path: Path,
    *,
    public_key: PublicKey | None = None,
    expect: str | None = None,
    exact: bool = False,
    check_evidence: bool = True,
) -> VerifyResult:
    """Verify one ledger file. ``ok`` is True only when there are no errors."""
    errors: list[Finding] = []
    warnings: list[Finding] = []
    if exact and expect is None:
        errors.append(
            Finding("error", "usage", "--exact requires --expect")
        )
        return VerifyResult(False, 0, None, errors, warnings)

    case_dir = ledger_path.parent
    if public_key is None:
        discovered = case_dir / "signing-key.pub"
        if discovered.is_file():
            try:
                public_key = load_public_key(discovered)
            except (OSError, ValueError) as exc:
                errors.append(
                    Finding("error", "public_key", f"signing-key.pub: {exc}")
                )

    try:
        raw = ledger_path.read_bytes()
    except OSError as exc:
        errors.append(Finding("error", "unreadable", str(exc)))
        return VerifyResult(False, 0, None, errors, warnings)

    if raw.startswith(b"\xef\xbb\xbf"):
        errors.append(Finding("error", "encoding", "UTF-8 BOM is not allowed"))
        return VerifyResult(False, 0, None, errors, warnings)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        errors.append(Finding("error", "encoding", f"ledger is not UTF-8: {exc}"))
        return VerifyResult(False, 0, None, errors, warnings)

    lines = text.splitlines()
    entries: list[dict[str, Any] | None] = []
    seen_signed = False
    needs_key = False

    for line_no, line in enumerate(lines, start=1):
        if line.strip() == "":
            errors.append(
                Finding("error", "blank_line", "blank line in ledger", line=line_no)
            )
            entries.append(None)
            continue
        try:
            parsed = json.loads(line, object_pairs_hook=_pairs_hook)
        except DuplicateKeyError as exc:
            errors.append(
                Finding(
                    "error",
                    "duplicate_key",
                    f"duplicate key {exc}",
                    line=line_no,
                )
            )
            entries.append(None)
            continue
        except json.JSONDecodeError as exc:
            errors.append(
                Finding("error", "malformed", f"line is not JSON: {exc.msg}", line=line_no)
            )
            entries.append(None)
            continue
        if not isinstance(parsed, dict):
            errors.append(
                Finding("error", "malformed", "line is not a JSON object", line=line_no)
            )
            entries.append(None)
            continue

        entry_errors = _check_entry(
            parsed,
            line_no=line_no,
            position=len(entries) + 1,
            previous=entries[-1] if entries else None,
            public_key=public_key,
            seen_signed=seen_signed,
        )
        for item in entry_errors:
            if item.code == "public_key_required":
                needs_key = True
            else:
                errors.append(item)
        if _is_signed_shape(parsed):
            seen_signed = True
        entries.append(parsed)

    if needs_key:
        errors.append(
            Finding(
                "error",
                "public_key_required",
                "signed entries present and no public key was available",
            )
        )

    parsed_entries = [entry for entry in entries if isinstance(entry, dict)]
    tip = _claimed_tip(parsed_entries)
    if not lines:
        errors.append(Finding("error", "empty", "ledger has no entries"))

    if expect is not None and not any(item.code == "usage" for item in errors):
        try:
            anchor_seq, anchor_hash = _parse_anchor(expect)
        except ValueError as exc:
            errors.append(Finding("error", "anchor_syntax", str(exc)))
        else:
            _check_anchor(
                errors,
                warnings,
                parsed_entries,
                anchor_seq,
                anchor_hash,
                exact,
            )

    if check_evidence:
        _check_evidence(errors, case_dir, parsed_entries)

    ok = not errors
    return VerifyResult(ok, len(parsed_entries), tip, errors, warnings)


def _is_signed_shape(entry: Mapping[str, Any]) -> bool:
    return "kid" in entry or "sig" in entry


def _claimed_tip(entries: Sequence[Mapping[str, Any]]) -> str | None:
    if not entries:
        return None
    last = entries[-1]
    seq = last.get("seq")
    digest = last.get("hash")
    if isinstance(seq, int) and not isinstance(seq, bool) and isinstance(digest, str):
        return f"{seq}:{digest}"
    return None


def _check_entry(
    entry: Mapping[str, Any],
    *,
    line_no: int,
    position: int,
    previous: Mapping[str, Any] | None,
    public_key: PublicKey | None,
    seen_signed: bool,
) -> list[Finding]:
    findings: list[Finding] = []

    def add(code: str, detail: str, seq: int | None = None) -> None:
        findings.append(Finding("error", code, detail, seq=seq, line=line_no))

    extra = sorted(set(entry) - ALLOWED_FIELDS)
    if extra:
        add("extra_field", "fields not in the format: " + ", ".join(extra))
    missing = sorted(REQUIRED_FIELDS - set(entry))
    if missing:
        add("missing_field", "missing fields: " + ", ".join(missing))
        return findings

    seq = entry["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int):
        add("seq", "seq must be an integer")
        seq_value: int | None = None
    elif seq != position or seq < 1:
        add("seq", f"seq is {seq}, expected {position}")
        seq_value = seq
    else:
        seq_value = seq

    if not _utc_timestamp(entry["ts"]):
        add("timestamp", "ts must be a UTC ISO 8601 time", seq_value)

    kind = entry["kind"]
    if kind not in KINDS:
        add("kind", f"kind {kind!r} is not a ledger kind", seq_value)

    if not isinstance(entry["payload"], dict):
        add("payload", "payload must be a JSON object", seq_value)

    prev = entry["prev"]
    if not _is_lower_hex(prev, 64):
        add("prev", "prev must be 64 lowercase hex characters", seq_value)
    elif position == 1:
        if prev != GENESIS_PREV:
            add("prev", "entry 1 prev must be 64 zeros", seq_value)
    elif isinstance(previous, dict) and _is_lower_hex(previous.get("hash"), 64):
        if prev != previous["hash"]:
            add("prev", "prev is not the previous entry's hash", seq_value)
    elif previous is None and position != 1:
        add("prev", "previous entry is missing or malformed", seq_value)

    if "actor" in entry and not isinstance(entry["actor"], str):
        add("actor", "actor must be a string", seq_value)
    if "kid" in entry and not _is_lower_hex(entry["kid"], 16):
        add("kid", "kid must be 16 lowercase hex characters", seq_value)

    digest = entry["hash"]
    computed: str | None = None
    if not _is_lower_hex(digest, 64):
        add("hash", "hash must be 64 lowercase hex characters", seq_value)
    else:
        try:
            computed = entry_hash(entry)
        except CanonicalError as exc:
            add("canonical", str(exc), seq_value)
        else:
            if computed != digest:
                add(
                    "hash",
                    "hash does not match the canonical entry",
                    seq_value,
                )

    _check_signature(
        add,
        entry,
        seq_value=seq_value,
        public_key=public_key,
        seen_signed=seen_signed,
    )
    return findings


def _check_signature(
    add: Any,
    entry: Mapping[str, Any],
    *,
    seq_value: int | None,
    public_key: PublicKey | None,
    seen_signed: bool,
) -> None:
    has_kid = "kid" in entry
    has_sig = "sig" in entry
    if not has_kid and not has_sig:
        if seen_signed:
            add(
                "unsigned_after_signed",
                "unsigned entry after signing began",
                seq_value,
            )
        return

    # kid is inside the hash and sig is not. Stripping sig leaves the hash
    # and any anchor unchanged, so a kid with no signature has to fail here
    # or the earliest signature can be removed without a trace.
    if not has_kid or not has_sig:
        add(
            "signature_incomplete",
            "signed entries require both kid and sig",
            seq_value,
        )
        return
    sig = entry["sig"]
    if not _is_lower_hex(sig, 128):
        add("sig", "sig must be 128 lowercase hex characters", seq_value)
        return
    if public_key is None:
        add(
            "public_key_required",
            "signature present but no public key was given",
            seq_value,
        )
        return
    kid = entry["kid"]
    if isinstance(kid, str) and kid != public_key.kid:
        add(
            "kid",
            f"kid {kid} is not the id of the provided public key",
            seq_value,
        )
    # The signature covers the 64 ASCII characters stored in ``hash``.
    # Whether that hash is the canonical digest is a separate check.
    message = entry.get("hash")
    if isinstance(message, str) and _is_lower_hex(message, 64):
        if not signature_valid(public_key, message, sig):
            add("sig", "Ed25519 signature does not verify", seq_value)


def _check_anchor(
    errors: list[Finding],
    warnings: list[Finding],
    entries: Sequence[Mapping[str, Any]],
    anchor_seq: int,
    anchor_hash: str,
    exact: bool,
) -> None:
    match = None
    for entry in entries:
        if entry.get("seq") == anchor_seq:
            match = entry
            break
    if match is None:
        errors.append(
            Finding(
                "error",
                "anchor_missing",
                f"no entry with seq {anchor_seq}",
                seq=anchor_seq,
            )
        )
        return
    if match.get("hash") != anchor_hash:
        errors.append(
            Finding(
                "error",
                "anchor_hash",
                f"entry {anchor_seq} hash is not the anchored hash",
                seq=anchor_seq,
            )
        )
        return
    later = [
        entry
        for entry in entries
        if isinstance(entry.get("seq"), int)
        and not isinstance(entry.get("seq"), bool)
        and entry["seq"] > anchor_seq
    ]
    if later and exact:
        errors.append(
            Finding(
                "error",
                "anchor_extended",
                f"{len(later)} entr{'y' if len(later) == 1 else 'ies'} after the anchor",
                seq=anchor_seq,
            )
        )
    elif later:
        warnings.append(
            Finding(
                "warning",
                "after_anchor",
                f"{len(later)} entr{'y' if len(later) == 1 else 'ies'} after the anchor are not covered",
                seq=anchor_seq,
            )
        )


def _check_evidence(
    errors: list[Finding],
    case_dir: Path,
    entries: Sequence[Mapping[str, Any]],
) -> None:
    referenced: list[tuple[int | None, str, str]] = []
    for entry in entries:
        if entry.get("kind") not in ARTIFACT_KINDS:
            continue
        payload = entry.get("payload")
        seq = entry.get("seq")
        seq_value = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
        if not isinstance(payload, dict):
            continue
        # The format spec says each artifact names stored_path and sha256.
        # It does not say those keys sit on the payload itself. Real
        # artifact.link entries put them on payload["artifact"]; accept
        # either place.
        artifact = payload.get("artifact")
        home = artifact if isinstance(artifact, dict) else payload
        stored = home.get("stored_path")
        digest = home.get("sha256")
        if not isinstance(stored, str) or not _is_lower_hex(digest, 64):
            errors.append(
                Finding(
                    "error",
                    "artifact_fields",
                    "artifact needs stored_path and lowercase sha256",
                    seq=seq_value,
                )
            )
            continue
        referenced.append((seq_value, stored, digest))

    evidence = case_dir / "evidence"
    if not referenced and not evidence.exists():
        return

    if evidence.is_symlink():
        errors.append(
            Finding("error", "evidence_link", "evidence/ is a symbolic link")
        )
        return
    if not evidence.is_dir():
        errors.append(Finding("error", "evidence_missing", "evidence/ is missing"))
        return

    listed: set[str] = set()
    for seq_value, stored, digest in referenced:
        try:
            rel = _relative_stored(stored)
        except ValueError as exc:
            errors.append(Finding("error", "stored_path", str(exc), seq=seq_value))
            continue
        listed.add(rel)
        path, linked = _walk_evidence(evidence, rel)
        if linked:
            errors.append(
                Finding(
                    "error",
                    "evidence_link",
                    f"{rel} is a symbolic link",
                    seq=seq_value,
                )
            )
            continue
        if not path.is_file():
            errors.append(
                Finding("error", "evidence_missing", f"{rel} is missing", seq=seq_value)
            )
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(
                Finding(
                    "error",
                    "evidence_hash",
                    f"{rel} sha256 does not match",
                    seq=seq_value,
                )
            )

    on_disk: set[str] = set()
    for path in evidence.rglob("*"):
        rel = path.relative_to(evidence).as_posix()
        if path.is_symlink():
            if rel not in listed:
                errors.append(
                    Finding(
                        "error",
                        "evidence_link",
                        f"evidence/{rel} is a symbolic link the ledger does not list",
                    )
                )
            continue
        if path.is_file():
            on_disk.add(rel)
    for rel in sorted(on_disk - listed):
        errors.append(
            Finding("error", "evidence_extra", f"evidence/{rel} is not listed")
        )


def _relative_stored(stored: str) -> str:
    raw = stored.replace("\\", "/")
    if raw.startswith("evidence/"):
        raw = raw[len("evidence/") :]
    parts = Path(raw).parts
    if not raw or raw.startswith("/") or ".." in parts or Path(raw).is_absolute():
        raise ValueError("stored_path must stay under evidence/")
    return "/".join(parts)


def _walk_evidence(evidence: Path, rel: str) -> tuple[Path, bool]:
    """Return the path and whether any component is a symbolic link.

    The walk does not follow links, so a link cannot redirect the hash
    read at a file outside evidence/.
    """
    current = evidence
    for part in rel.split("/"):
        current = current / part
        if current.is_symlink():
            return current, True
    return current, False


def _format_human(result: VerifyResult) -> str:
    lines: list[str] = []
    state = "OK" if result.ok else "FAIL"
    tip = result.tip or "-"
    lines.append(f"{state} entries={result.entries} tip={tip}")
    for item in result.errors:
        where = []
        if item.line is not None:
            where.append(f"line {item.line}")
        if item.seq is not None:
            where.append(f"seq {item.seq}")
        prefix = (" (" + ", ".join(where) + ")") if where else ""
        lines.append(f"error {item.code}{prefix}: {item.detail}")
    for item in result.warnings:
        where = f" seq {item.seq}" if item.seq is not None else ""
        lines.append(f"warning {item.code}{where}: {item.detail}")
    return "\n".join(lines)


def verify_path(
    path: Path,
    *,
    public_key_path: Path | None = None,
    expect: str | None = None,
    exact: bool = False,
    check_evidence: bool = True,
) -> VerifyResult:
    if path.is_dir():
        ledger = path / "ledger.jsonl"
    else:
        ledger = path
    public_key = None
    errors: list[Finding] = []
    if public_key_path is not None:
        try:
            public_key = load_public_key(public_key_path)
        except (OSError, ValueError) as exc:
            errors.append(Finding("error", "public_key", str(exc)))
            return VerifyResult(False, 0, None, errors, [])
    if not ledger.is_file():
        errors.append(Finding("error", "unreadable", f"{ledger} is not a file"))
        return VerifyResult(False, 0, None, errors, [])
    return verify_ledger(
        ledger,
        public_key=public_key,
        expect=expect,
        exact=exact,
        check_evidence=check_evidence,
    )


def self_test() -> None:
    """Recompute the spec's worked example with hashlib and cryptography."""
    entry1 = {
        "seq": 1,
        "ts": "2026-10-22T00:00:00+00:00",
        "kind": "case.create",
        "payload": {"id": "kat", "title": "Résumé — test"},
        "prev": GENESIS_PREV,
    }
    got1 = canonical_bytes(entry1).decode("utf-8")
    if got1 != _SPEC_ENTRY1:
        raise SystemExit("canonical entry 1 does not match the spec worked example")
    if entry_hash(entry1) != _SPEC_ENTRY1_HASH:
        raise SystemExit("entry 1 hash does not match the spec")

    entry2 = {
        "actor": "alex",
        "kid": _SPEC_KID,
        "kind": "event.add",
        "payload": {"decision": "Denied", "id": "EVT-0001"},
        "prev": _SPEC_ENTRY1_HASH,
        "seq": 2,
        "ts": "2026-10-22T00:00:01+00:00",
    }
    got2 = canonical_bytes(covered_object(entry2)).decode("utf-8")
    if got2 != _SPEC_ENTRY2:
        raise SystemExit("canonical entry 2 does not match the spec worked example")
    if entry_hash(entry2) != _SPEC_ENTRY2_HASH:
        raise SystemExit("entry 2 hash does not match the spec")

    public_key = public_key_from_raw(bytes.fromhex(_SPEC_PUB_HEX))
    if public_key.kid != _SPEC_KID:
        raise SystemExit("key id does not match the spec")
    if not signature_valid(public_key, _SPEC_ENTRY2_HASH, _SPEC_ENTRY2_SIG):
        raise SystemExit("worked-example signature did not verify")

    line1 = json.dumps(
        {**entry1, "hash": _SPEC_ENTRY1_HASH},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    line2 = json.dumps(
        {**entry2, "hash": _SPEC_ENTRY2_HASH, "sig": _SPEC_ENTRY2_SIG},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        ledger = root / "ledger.jsonl"
        pub = root / "signing-key.pub"
        pub.write_text(_SPEC_PUB_HEX + "\n", encoding="ascii")
        ledger.write_text(line1 + "\n" + line2 + "\n", encoding="utf-8")
        ok = verify_ledger(ledger, check_evidence=False)
        if not ok.ok:
            raise SystemExit(f"worked example failed: {ok.errors}")

        # Reordered keys stay valid: the hash is over sorted keys.
        reordered = json.loads(line1)
        rotated = json.dumps(
            {key: reordered[key] for key in reversed(list(reordered))},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        ledger.write_text(rotated + "\n" + line2 + "\n", encoding="utf-8")
        if not verify_ledger(ledger, check_evidence=False).ok:
            raise SystemExit("reordered keys were rejected")

        # \\u escapes decode before the hash is computed.
        escaped = line1.replace("é", r"\u00e9").replace("—", r"\u2014")
        ledger.write_text(escaped + "\n" + line2 + "\n", encoding="utf-8")
        if not verify_ledger(ledger, check_evidence=False).ok:
            raise SystemExit("unicode escapes were rejected")

        # Stripping sig leaves the hash intact, and must still fail.
        stripped = json.loads(line2)
        del stripped["sig"]
        ledger.write_text(
            line1 + "\n" + json.dumps(stripped, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        stripped_result = verify_ledger(ledger, check_evidence=False)
        if stripped_result.ok or not any(
            item.code == "signature_incomplete" for item in stripped_result.errors
        ):
            raise SystemExit("stripped signature was not rejected")

        # Lone surrogate cannot be canonical UTF-8.
        surrogate_line = line1.replace("test", "test\\uD800")
        ledger.write_text(surrogate_line + "\n", encoding="utf-8")
        surrogate = verify_ledger(ledger, check_evidence=False)
        if surrogate.ok or not any(
            item.code in {"canonical", "hash"} for item in surrogate.errors
        ):
            raise SystemExit("lone surrogate was not rejected")

        bad_sig = dict(json.loads(line2))
        bad_sig["sig"] = "é" + _SPEC_ENTRY2_SIG[1:]
        ledger.write_text(
            line1
            + "\n"
            + json.dumps(bad_sig, ensure_ascii=False, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        non_ascii = verify_ledger(ledger, check_evidence=False)
        if non_ascii.ok or not any(item.code == "sig" for item in non_ascii.errors):
            raise SystemExit("non-ASCII signature was not rejected")

        anchor = f"2:{_SPEC_ENTRY2_HASH}"
        ledger.write_text(line1 + "\n" + line2 + "\n", encoding="utf-8")
        exact = verify_ledger(
            ledger, expect=anchor, exact=True, check_evidence=False
        )
        if not exact.ok:
            raise SystemExit("exact anchor rejected the worked example")

        # Anchor extension is checked on an unsigned chain so the result
        # is the anchor rule, not the "unsigned after signed" rule.
        unsigned2 = {
            "seq": 2,
            "ts": "2026-10-22T00:00:01+00:00",
            "kind": "event.add",
            "payload": {"decision": "Denied", "id": "EVT-0001"},
            "prev": _SPEC_ENTRY1_HASH,
        }
        unsigned2["hash"] = entry_hash(unsigned2)
        unsigned_line = json.dumps(unsigned2, separators=(",", ":"), sort_keys=True)
        anchor1 = f"1:{_SPEC_ENTRY1_HASH}"
        # No signing-key.pub here: this chain is unsigned on purpose.
        pub.unlink()
        ledger.write_text(line1 + "\n" + unsigned_line + "\n", encoding="utf-8")
        held = verify_ledger(ledger, expect=anchor1, exact=False, check_evidence=False)
        if not held.ok:
            raise SystemExit(f"non-exact anchor rejected a later entry: {held.errors}")
        if not any(item.code == "after_anchor" for item in held.warnings):
            raise SystemExit("non-exact anchor did not report entries after it")
        tight = verify_ledger(ledger, expect=anchor1, exact=True, check_evidence=False)
        if tight.ok or not any(
            item.code == "anchor_extended" for item in tight.errors
        ):
            raise SystemExit("--exact did not reject an append")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a ledger.jsonl from the format spec.")
    parser.add_argument("path", nargs="?", type=Path, help="case directory or ledger.jsonl")
    parser.add_argument("--public-key", type=Path, help="Ed25519 public key (PEM or raw hex)")
    parser.add_argument("--expect", help="anchor as <seq>:<hash>")
    parser.add_argument(
        "--exact",
        action="store_true",
        help="anchor entry must be the last entry",
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    parser.add_argument(
        "--no-evidence",
        action="store_true",
        help="do not check evidence/ files",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="check the spec worked example and exit",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        print("self-test ok")
        return 0
    if args.path is None:
        parser.error("path is required unless --self-test is set")
    result = verify_path(
        args.path,
        public_key_path=args.public_key,
        expect=args.expect,
        exact=args.exact,
        check_evidence=not args.no_evidence,
    )
    if args.json:
        json.dump(result.to_json(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(_format_human(result))
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
