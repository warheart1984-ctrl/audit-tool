"""Case workspace on disk.

    cases/
      <case-id>/
        ledger.jsonl      append-only, hash-chained history
        evidence/         byte-for-byte copies of ingested files, named by hash
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path

from .ledger import Ledger, now_iso
from .models import EDITABLE, Artifact, Event


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Case:
    def __init__(self, directory: Path):
        self.dir = directory
        self.ledger = Ledger(directory / "ledger.jsonl")
        self.evidence_dir = directory / "evidence"

    @property
    def id(self) -> str:
        return self.dir.name

    def info(self) -> dict:
        for entry in self.ledger.entries():
            if entry["kind"] == "case.create":
                return entry["payload"]
        return {"id": self.id}

    def replay(self) -> tuple[dict[str, Event], list[str]]:
        """Rebuild every event's current state from the ledger.

        Entries that can't apply (an update to an event that doesn't exist, a
        duplicate event id, an unknown field) are skipped and reported rather
        than aborting, so one bad line can't make the whole case unreadable.
        """
        events: dict[str, Event] = {}
        problems: list[str] = []
        for entry in self.ledger.entries():
            seq, kind, p = entry.get("seq"), entry.get("kind"), entry.get("payload") or {}
            if kind == "event.add":
                if p.get("id") in events:
                    problems.append(f"entry {seq}: duplicate event id {p.get('id')} (ignored)")
                    continue
                events[p.get("id")] = Event.from_dict(p)
            elif kind in ("event.update", "artifact.link"):
                target = p.get("id") if kind == "event.update" else p.get("event_id")
                if target not in events:
                    problems.append(f"entry {seq}: {kind} refers to unknown event {target} (ignored)")
                    continue
                ev = events[target]
                if kind == "artifact.link":
                    ev.artifacts.append(p.get("artifact") or {})
                    continue
                for name, value in (p.get("changes") or {}).items():
                    if name not in EDITABLE:
                        problems.append(f"entry {seq}: update to non-editable field '{name}' (ignored)")
                        continue
                    setattr(ev, name, value)
                    ev.origin[name] = "confirmed"
            elif kind != "case.create":
                problems.append(f"entry {seq}: unknown entry kind '{kind}' (ignored)")
        return events, problems

    def events(self) -> dict[str, Event]:
        return self.replay()[0]

    def next_event_id(self) -> str:
        # One past the highest id ever added, so ids are never reused even if
        # the ledger contains out-of-order or hand-made entries.
        highest = 0
        for e in self.ledger.entries():
            if e.get("kind") == "event.add":
                m = re.fullmatch(r"EVT-(\d+)", str((e.get("payload") or {}).get("id", "")))
                if m:
                    highest = max(highest, int(m.group(1)))
        return f"EVT-{highest + 1:04d}"

    def store_artifact(self, src: Path) -> dict:
        """Copy a file into the evidence folder (idempotent by content hash)."""
        digest = sha256_file(src)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", src.name)
        dest = self.evidence_dir / f"{digest[:12]}_{safe}"
        if not dest.exists():
            shutil.copy2(src, dest)
        return Artifact(
            sha256=digest,
            stored_path=dest.relative_to(self.dir).as_posix(),
            original_name=src.name,
            size=src.stat().st_size,
            added_at=now_iso(),
        ).__dict__

    def store_derived_text(self, source: dict, text: str, method: str) -> dict:
        """Save text recovered from an artifact (OCR, PDF text layer) next to the original."""
        stem = Path(source["stored_path"]).name
        dest = self.evidence_dir / f"{stem}.extracted.txt"
        dest.write_text(text, encoding="utf-8", newline="\n")
        artifact = Artifact(
            sha256=sha256_file(dest),
            stored_path=dest.relative_to(self.dir).as_posix(),
            original_name=dest.name,
            size=dest.stat().st_size,
            added_at=now_iso(),
        ).__dict__
        artifact.update({"derived_from": source["sha256"], "method": method})
        return artifact

    def add_event(self, event: Event, *artifacts: dict) -> Event:
        payload = event.to_dict()
        payload["artifacts"] = []
        self.ledger.append("event.add", payload)
        for artifact in artifacts:
            self.ledger.append("artifact.link", {"event_id": event.id, "artifact": artifact})
        return event

    def update_event(self, event_id: str, changes: dict, reason: str) -> None:
        if event_id not in self.events():
            raise KeyError(f"No event {event_id} in case {self.id}")
        self.ledger.append("event.update", {"id": event_id, "changes": changes, "reason": reason})

    def link_artifact(self, event_id: str, src: Path) -> dict:
        if event_id not in self.events():
            raise KeyError(f"No event {event_id} in case {self.id}")
        artifact = self.store_artifact(src)
        self.ledger.append("artifact.link", {"event_id": event_id, "artifact": artifact})
        return artifact

    def verify(self, expect_head: str | None = None) -> list[str]:
        """Check the ledger chain, every recorded evidence file, and the evidence folder.

        `expect_head` is a head hash saved earlier (see `Ledger.head`). The chain
        alone can't detect a wholesale rewrite; a hash kept somewhere else can.
        """
        problems = self.ledger.verify()
        if problems and problems[0].startswith("line "):
            return problems  # unreadable ledger: nothing below can be trusted
        if expect_head:
            if not self.ledger.contains(expect_head):
                problems.append(f"anchored head {expect_head} is not in this ledger: "
                                "history recorded before it was rewritten or replaced")
        events, replay_problems = self.replay()
        problems += replay_problems

        case_root = self.dir.resolve()
        recorded = set()
        for ev in events.values():
            for art in ev.artifacts:
                rel = str(art.get("stored_path", ""))
                if rel in recorded:
                    continue
                recorded.add(rel)
                path = self.dir / rel
                if not path.resolve().is_relative_to(case_root) or not rel.startswith("evidence/"):
                    problems.append(f"{rel}: recorded evidence path points outside the evidence folder")
                elif path.is_symlink():
                    problems.append(f"{rel}: evidence file is a symbolic link")
                elif not path.is_file():
                    problems.append(f"{rel}: evidence file is missing")
                elif sha256_file(path) != art.get("sha256"):
                    problems.append(f"{rel}: evidence file changed since it was recorded")

        # An evidence folder should hold exactly what the ledger lists.
        if self.evidence_dir.exists():
            for path in sorted(self.evidence_dir.rglob("*")):
                rel = path.relative_to(self.dir).as_posix()
                if path.is_symlink() and rel not in recorded:
                    problems.append(f"{rel}: symbolic link in the evidence folder")
                elif path.is_file() and rel not in recorded:
                    problems.append(f"{rel}: file in the evidence folder is not recorded in the ledger")
        return problems


CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class Workspace:
    def __init__(self, root: Path):
        self.root = root

    def _case_dir(self, case_id: str) -> Path:
        """Map a case id to its folder, refusing anything that could leave the workspace."""
        if not CASE_ID.fullmatch(case_id) or ".." in case_id:
            raise ValueError("Case id must start with a letter or digit and contain only "
                             "letters, digits, '.', '_' and '-' (no '..')")
        directory = self.root / case_id
        root = self.root.resolve()
        if directory.resolve().parent != root:
            raise ValueError(f"Case id '{case_id}' does not resolve to a folder directly inside {root}")
        return directory

    def create_case(self, case_id: str, title: str, subject: str = "", institution: str = "") -> Case:
        directory = self._case_dir(case_id)
        if (directory / "ledger.jsonl").exists():
            raise FileExistsError(f"Case {case_id} already exists at {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        case = Case(directory)
        case.ledger.append("case.create", {
            "id": case_id, "title": title, "subject": subject,
            "institution": institution, "created_at": now_iso(),
        })
        return case

    def open_case(self, case_id: str) -> Case:
        directory = self._case_dir(case_id)
        if not (directory / "ledger.jsonl").exists():
            raise FileNotFoundError(f"No case '{case_id}' under {self.root}")
        return Case(directory)

    def list_cases(self) -> list[Case]:
        if not self.root.exists():
            return []
        return [Case(d) for d in sorted(self.root.iterdir())
                if CASE_ID.fullmatch(d.name) and ".." not in d.name and (d / "ledger.jsonl").exists()]
