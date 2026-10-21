"""Append-only, hash-chained ledger.

Every change to a case (new event, correction, attached file) is an entry whose
hash covers its content and the previous entry's hash. Editing or deleting any
past line breaks the chain, which `verify()` reports. Current state is rebuilt by
replaying the entries, so the full history of who-changed-what stays on record.

What the chain can't show on its own: someone with write access can replace the
whole file with a new, internally consistent chain. The defence is the head hash
(`head()`): save it somewhere outside this machine (email it, give it to the
other party), and `contains()` later proves the history up to that point is
unchanged, because entries are only ever appended after it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _entry_hash(entry: dict) -> str:
    body = {k: entry[k] for k in ("seq", "ts", "kind", "payload", "prev")}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Ledger:
    def __init__(self, path: Path):
        self.path = path

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
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

    def head(self) -> str:
        """Hash of the latest entry. Saved elsewhere, it anchors everything up to it."""
        entries = self.entries()
        return entries[-1]["hash"] if entries else GENESIS

    def contains(self, digest: str) -> bool:
        digest = digest.strip().lower()
        return len(digest) == 64 and any(e.get("hash") == digest for e in self.entries())

    def append(self, kind: str, payload: dict) -> dict:
        existing = self.entries()
        prev = existing[-1]["hash"] if existing else GENESIS
        entry = {"seq": len(existing) + 1, "ts": now_iso(), "kind": kind, "payload": payload, "prev": prev}
        entry["hash"] = _entry_hash(entry)
        with self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> list[str]:
        try:
            entries = self.entries()
        except ValueError as exc:
            return [f"line unreadable: {exc}"]
        problems = []
        prev = GENESIS
        for i, entry in enumerate(entries, start=1):
            if entry.get("seq") != i:
                problems.append(f"entry {i}: sequence number is {entry.get('seq')}, expected {i}")
            if entry.get("prev") != prev:
                problems.append(f"entry {i}: chain broken (prev hash does not match entry {i - 1})")
            try:
                intact = _entry_hash(entry) == entry.get("hash")
            except KeyError:
                intact = False
            if not intact:
                problems.append(f"entry {i}: content does not match its hash (modified after recording)")
            prev = entry.get("hash")
        return problems
