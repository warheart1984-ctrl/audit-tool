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
from .models import Artifact, Event


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

    def events(self) -> dict[str, Event]:
        """Replay the ledger into the current state of every event."""
        events: dict[str, Event] = {}
        for entry in self.ledger.entries():
            kind, p = entry["kind"], entry["payload"]
            if kind == "event.add":
                events[p["id"]] = Event.from_dict(p)
            elif kind == "event.update":
                ev = events[p["id"]]
                for name, value in p["changes"].items():
                    setattr(ev, name, value)
                    ev.origin[name] = "confirmed"
            elif kind == "artifact.link":
                events[p["event_id"]].artifacts.append(p["artifact"])
        return events

    def next_event_id(self) -> str:
        n = sum(1 for e in self.ledger.entries() if e["kind"] == "event.add")
        return f"EVT-{n + 1:04d}"

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

    def verify(self) -> list[str]:
        problems = self.ledger.verify()
        seen = set()
        for ev in self.events().values():
            for art in ev.artifacts:
                if art["stored_path"] in seen:
                    continue
                seen.add(art["stored_path"])
                path = self.dir / art["stored_path"]
                if not path.exists():
                    problems.append(f"{art['stored_path']}: evidence file is missing")
                elif sha256_file(path) != art["sha256"]:
                    problems.append(f"{art['stored_path']}: evidence file changed since it was recorded")
        return problems


class Workspace:
    def __init__(self, root: Path):
        self.root = root

    def create_case(self, case_id: str, title: str, subject: str = "", institution: str = "") -> Case:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", case_id):
            raise ValueError("Case id may only contain letters, digits, '.', '_' and '-'")
        directory = self.root / case_id
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
        directory = self.root / case_id
        if not (directory / "ledger.jsonl").exists():
            raise FileNotFoundError(f"No case '{case_id}' under {self.root}")
        return Case(directory)

    def list_cases(self) -> list[Case]:
        if not self.root.exists():
            return []
        return [Case(d) for d in sorted(self.root.iterdir()) if (d / "ledger.jsonl").exists()]
