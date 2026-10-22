"""Append-only, hash-chained ledger.

Every change to a case (new event, correction, attached file) is an entry whose
hash covers its content and the previous entry's hash. Editing or deleting any
past line breaks the chain, which `verify()` reports. Current state is rebuilt by
replaying the entries, so the full history of who-changed-what stays on record.

What the chain can't show on its own, and the defences:

* Someone with write access can replace the whole file with a new, internally
  consistent chain, or append or delete entries after a point you trusted. An
  anchor (`anchor()`, "<seq>:<hash>") saved off this machine proves the history
  up to that entry is unchanged and still at that position. `exact=True` also
  proves nothing was added or removed after it, so save a new anchor whenever
  you finish working on a case.
* Nothing in a bare entry says who wrote it. With an Ed25519 private key (kept
  outside the cases folder), each entry records an `actor`, the key id `kid` and
  a signature over its hash. Anyone holding only the public key can check the
  signatures but cannot forge new ones, so the public key can be handed to the
  other side. Whoever holds the private key is trusted.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
REQUIRED_KEYS = {"seq", "ts", "kind", "payload", "prev", "hash"}
OPTIONAL_KEYS = {"actor", "kid", "sig"}
LOCK_TIMEOUT = 15.0  # seconds to wait for another writer
STALE_LOCK = 60.0  # a lock older than this was left by a crashed writer


class LedgerUnreadable(ValueError):
    """The ledger file can't be parsed into entries. Always an integrity failure."""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _entry_hash(entry: dict) -> str:
    body = {k: entry[k] for k in ("seq", "ts", "kind", "payload", "prev")}
    for k in ("actor", "kid"):  # who wrote it and with which key are part of what's committed to
        if k in entry:
            body[k] = entry[k]
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --- Keys ---------------------------------------------------------------------

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        raise ValueError('signing needs the "cryptography" package: pip install ".[sign]"') from None
    return serialization, ed25519


def public_bytes(public_key) -> bytes:
    serialization, _ = _crypto()
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_key) -> str:
    """Short fingerprint of a public key. Save it off this machine with your anchors."""
    return hashlib.sha256(public_bytes(public_key)).hexdigest()[:16]


def generate_keypair() -> tuple[bytes, bytes]:
    """New Ed25519 key pair as (private PEM, public PEM)."""
    serialization, ed25519 = _crypto()
    private = ed25519.Ed25519PrivateKey.generate()
    priv_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
    pub_pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def load_private_key(path: Path):
    serialization, ed25519 = _crypto()
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"could not read private key {path}: {exc}") from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key (create one with `audit keygen`)")
    return key


def load_public_key(path: Path):
    serialization, ed25519 = _crypto()
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"could not read public key {path}: {exc}") from None
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def public_pem(public_key) -> bytes:
    serialization, _ = _crypto()
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def parse_anchor(text: str) -> tuple[int | None, str]:
    """'<seq>:<hash>' or a bare hash -> (seq or None, lower-case hash)."""
    text = text.strip().lower()
    if ":" in text:
        seq, _, digest = text.partition(":")
        if not seq.isdigit():
            raise ValueError(f"anchor '{text}' should look like <seq>:<hash>")
        return int(seq), digest
    return None, text


class Ledger:
    def __init__(self, path: Path, signer=None, verify_key=None, actor: str | None = None):
        self.path = path
        self.signer = signer
        self.verify_key = verify_key or (signer.public_key() if signer else None)
        self.kid = key_id(self.verify_key) if self.verify_key else None
        self.actor = actor or (f"key:{self.kid}" if signer else None)
        self._cache: tuple[tuple[int, int], list[dict]] | None = None
        self._lock_depth = 0

    def _read(self) -> list[dict]:
        out = []
        try:
            with self.path.open(encoding="utf-8") as fh:
                for n, line in enumerate(fh, start=1):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        raise LedgerUnreadable(f"ledger {self.path} line {n} is not valid JSON") from None
                    if not isinstance(entry, dict):
                        raise LedgerUnreadable(f"ledger {self.path} line {n} is not a ledger entry")
                    try:
                        # A JSON escape like \ud800 decodes to a lone surrogate, which has no UTF-8
                        # form, so the entry can't be hashed canonically. Reject it here, as an
                        # integrity failure, rather than crash later while hashing.
                        json.dumps(entry, ensure_ascii=False).encode("utf-8")
                    except UnicodeEncodeError:
                        raise LedgerUnreadable(f"ledger {self.path} line {n} contains text that is not valid "
                                               "Unicode (a lone surrogate), so it can't be hashed") from None
                    out.append(entry)
        except UnicodeDecodeError as exc:
            raise LedgerUnreadable(f"ledger {self.path} is not valid UTF-8 ({exc.reason} at byte {exc.start})") \
                from None
        return out

    def entries(self, fresh: bool = False) -> list[dict]:
        """Parsed entries. Cached until the file's size or mtime changes; treat as read-only.

        `fresh=True` re-reads unconditionally. Integrity checks use it, because a
        tamperer can restore a file's size and timestamp.
        """
        if not self.path.exists():
            return []
        st = self.path.stat()
        stamp = (st.st_size, st.st_mtime_ns)
        if not fresh and self._cache and self._cache[0] == stamp:
            return self._cache[1]
        entries = self._read()
        self._cache = (stamp, entries)
        return entries

    @contextmanager
    def locked(self):
        """Exclusive write access across processes (re-entrant within one Ledger).

        Without it, simultaneous appends interleave or, on Windows, overwrite one
        another, so entries are silently lost.
        """
        if self._lock_depth:
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
            return
        lock = self.path.with_name(self.path.name + ".lock")
        deadline = time.monotonic() + LOCK_TIMEOUT
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                break
            except (FileExistsError, PermissionError):
                try:
                    if time.time() - lock.stat().st_mtime > STALE_LOCK:
                        lock.unlink(missing_ok=True)
                        continue
                except (FileNotFoundError, PermissionError):
                    continue
                if time.monotonic() > deadline:
                    raise TimeoutError(f"another process has held {lock} for over {LOCK_TIMEOUT:.0f}s") from None
                time.sleep(0.005)
        self._lock_depth = 1
        try:
            yield
        finally:
            self._lock_depth = 0
            os.close(fd)
            try:
                lock.unlink()
            except FileNotFoundError:
                pass

    def append(self, kind: str, payload: dict) -> dict:
        with self.locked():
            existing = self.entries()
            prev = existing[-1]["hash"] if existing else GENESIS
            entry = {"seq": len(existing) + 1, "ts": now_iso(), "kind": kind, "payload": payload, "prev": prev}
            if self.actor:
                entry["actor"] = self.actor
            if self.signer:
                entry["kid"] = self.kid
            entry["hash"] = _entry_hash(entry)
            if self.signer:
                entry["sig"] = self.signer.sign(entry["hash"].encode("ascii")).hex()
            # Created owner-only; the ledger describes private matters.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def head(self) -> str:
        """Hash of the latest entry."""
        entries = self.entries()
        return entries[-1]["hash"] if entries else GENESIS

    def anchor(self) -> str:
        """'<seq>:<hash>' of the latest entry. Save it off this machine."""
        entries = self.entries()
        return f"{len(entries)}:{entries[-1]['hash']}" if entries else f"0:{GENESIS}"

    def position(self, anchor: str) -> int | None:
        """1-based position of the anchored entry, or None if it isn't where the anchor says."""
        seq, digest = parse_anchor(anchor)
        if len(digest) != 64:
            return None
        entries = self.entries(fresh=True)
        if seq is not None:
            return seq if 1 <= seq <= len(entries) and entries[seq - 1].get("hash") == digest else None
        for i, e in enumerate(entries, start=1):
            if e.get("hash") == digest:
                return i
        return None

    def contains(self, anchor: str) -> bool:
        return self.position(anchor) is not None

    def verify(self) -> list[str]:
        try:
            entries = self.entries(fresh=True)
        except ValueError as exc:
            return [f"line unreadable: {exc}"]
        problems = []
        prev = GENESIS
        for i, entry in enumerate(entries, start=1):
            missing = REQUIRED_KEYS - entry.keys()
            extra = entry.keys() - REQUIRED_KEYS - OPTIONAL_KEYS
            if missing:
                problems.append(f"entry {i}: missing field(s) {', '.join(sorted(missing))}")
            if extra:
                # Fields outside the hash would read as part of the record without being committed to.
                problems.append(f"entry {i}: unexpected field(s) {', '.join(sorted(extra))} not covered by the hash")
            if entry.get("seq") != i:
                problems.append(f"entry {i}: sequence number is {entry.get('seq')}, expected {i}")
            if entry.get("prev") != prev:
                problems.append(f"entry {i}: chain broken (prev hash does not match entry {i - 1})")
            try:
                intact = _entry_hash(entry) == entry.get("hash")
            except (KeyError, TypeError):
                intact = False
            if not intact:
                problems.append(f"entry {i}: content does not match its hash (modified after recording)")
            if "kid" in entry and "sig" not in entry:
                # `kid` is covered by the hash and `sig` is not, so a signature can be deleted
                # without breaking the chain; the leftover key id is what gives it away. Checked
                # here, without any key, so every command that verifies catches it.
                problems.append(f"entry {i}: signature removed (entry names signing key {entry['kid']} "
                                "but carries no signature)")
            prev = entry.get("hash")
        if self.verify_key is not None:
            problems += self._verify_signatures(entries)
        return problems

    def unsigned_prefix(self) -> int:
        """Number of unsigned entries before the first signed one (history from before signing began).

        An entry that names a key (`kid`) was signed, even if its signature is now missing.
        """
        n = 0
        for e in self.entries(fresh=True):
            if "sig" in e or "kid" in e:
                return n
            n += 1
        return n

    def is_signed(self) -> bool:
        return any("sig" in e for e in self.entries())

    def _verify_signatures(self, entries: list[dict]) -> list[str]:
        from cryptography.exceptions import InvalidSignature

        problems = []
        signing_started = False
        for i, entry in enumerate(entries, start=1):
            sig = entry.get("sig")
            if sig is None:
                if "kid" in entry:
                    # Was signed; its missing signature is reported by verify(). Signing began here.
                    signing_started = True
                    continue
                # Unsigned history from before signing was turned on is allowed; a gap after it is not.
                if signing_started:
                    problems.append(f"entry {i}: unsigned entry after signing began (written without the key)")
                continue
            signing_started = True
            if entry.get("kid") != self.kid:
                problems.append(f"entry {i}: signed by another key (kid {entry.get('kid')}, expected {self.kid})")
                continue
            try:
                self.verify_key.verify(bytes.fromhex(str(sig)), str(entry.get("hash")).encode("ascii"))
            except (InvalidSignature, ValueError):
                problems.append(f"entry {i}: signature is invalid (forged or altered)")
        if entries and not signing_started:
            problems.append("no entry is signed with this key")
        return problems
