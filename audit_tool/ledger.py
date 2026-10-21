"""Append-only, hash-chained ledger.

Every change to a case (new event, correction, attached file) is an entry whose
hash covers its content and the previous entry's hash. Editing or deleting any
past line breaks the chain, which `verify()` reports. Current state is rebuilt by
replaying the entries, so the full history of who-changed-what stays on record.

What the chain can't show on its own, and the two defences:

* Someone with write access can replace the whole file with a new, internally
  consistent chain, or append entries after a point you trusted. The head hash
  (`head()`) saved somewhere off this machine proves the history *up to it* is
  unchanged (`contains()`); entries after it are not covered until you save a
  newer head.
* Nothing in a bare entry says who wrote it. With a key (kept outside the cases
  folder), each entry records an `actor` and an HMAC-SHA256 `sig` over its hash,
  and `verify()` flags unsigned or wrongly signed entries. This stops other
  people and processes that can write the file but don't hold the key. It does
  not stop whoever holds the key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
REQUIRED_KEYS = {"seq", "ts", "kind", "payload", "prev", "hash"}
OPTIONAL_KEYS = {"actor", "sig"}
LOCK_TIMEOUT = 15.0  # seconds to wait for another writer
STALE_LOCK = 60.0  # a lock older than this was left by a crashed writer


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _entry_hash(entry: dict) -> str:
    body = {k: entry[k] for k in ("seq", "ts", "kind", "payload", "prev")}
    if "actor" in entry:
        body["actor"] = entry["actor"]  # the author is part of what the hash commits to
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def sign(key: bytes, digest: str) -> str:
    return hmac.new(key, digest.encode("ascii"), hashlib.sha256).hexdigest()


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(b"audit-tool key id:" + key).hexdigest()[:12]


class Ledger:
    def __init__(self, path: Path, key: bytes | None = None, actor: str | None = None):
        self.path = path
        self.key = key
        self.actor = actor or (f"key:{key_fingerprint(key)}" if key else None)
        self._cache: tuple[tuple[int, int], list[dict]] | None = None
        self._lock_depth = 0

    def _read(self) -> list[dict]:
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for n, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    raise ValueError(f"ledger {self.path} line {n} is not valid JSON") from None
                if not isinstance(entry, dict):
                    raise ValueError(f"ledger {self.path} line {n} is not a ledger entry")
                out.append(entry)
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
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
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
            entry["hash"] = _entry_hash(entry)
            if self.key:
                entry["sig"] = sign(self.key, entry["hash"])
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def head(self) -> str:
        """Hash of the latest entry. Saved elsewhere, it anchors everything up to it."""
        entries = self.entries()
        return entries[-1]["hash"] if entries else GENESIS

    def position(self, digest: str) -> int | None:
        """1-based position of the entry with this hash, or None."""
        digest = digest.strip().lower()
        if len(digest) != 64:
            return None
        for i, e in enumerate(self.entries(fresh=True), start=1):
            if e.get("hash") == digest:
                return i
        return None

    def contains(self, digest: str) -> bool:
        return self.position(digest) is not None

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
            prev = entry.get("hash")
        if self.key:
            problems += self._verify_signatures(entries)
        return problems

    def unsigned_prefix(self) -> int:
        """Number of unsigned entries before the first signed one (history from before signing began)."""
        n = 0
        for e in self.entries(fresh=True):
            if "sig" in e:
                return n
            n += 1
        return n

    def _verify_signatures(self, entries: list[dict]) -> list[str]:
        problems = []
        signing_started = False
        for i, entry in enumerate(entries, start=1):
            sig = entry.get("sig")
            if sig is None:
                # Unsigned history from before signing was turned on is allowed; a gap after it is not.
                if signing_started:
                    problems.append(f"entry {i}: unsigned entry after signing began (written without the key)")
                continue
            signing_started = True
            if not isinstance(sig, str) or not hmac.compare_digest(sig, sign(self.key, str(entry.get("hash")))):
                problems.append(f"entry {i}: signature does not match this key (forged, or signed with another key)")
        if entries and not signing_started:
            problems.append("no entry is signed with this key")
        return problems
