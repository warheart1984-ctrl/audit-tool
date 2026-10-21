"""Case workspace on disk.

    cases/
      <case-id>/
        ledger.jsonl      append-only, hash-chained (optionally signed) history
        evidence/         byte-for-byte copies of ingested files, named by hash
"""

from __future__ import annotations

import copy
import hashlib
import re
import shutil
from dataclasses import fields as dataclass_fields
from pathlib import Path

from .ledger import Ledger, now_iso
from .models import EDITABLE, Artifact, Event

_STR_FIELDS = {f.name for f in dataclass_fields(Event) if f.type == "str"}
EVENT_ID = re.compile(r"EVT-\d{1,9}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _event_payload_problem(p) -> str | None:
    if not isinstance(p, dict):
        return "payload is not an object"
    if not isinstance(p.get("id"), str) or not EVENT_ID.fullmatch(p["id"]):
        return "event id is missing or malformed"
    for name in _STR_FIELDS & p.keys():
        if not isinstance(p[name], str):
            return f"field '{name}' is not text"
    if not isinstance(p.get("origin", {}), dict) or not isinstance(p.get("artifacts", []), list):
        return "origin/artifacts have the wrong shape"
    return None


def _artifact_problem(a) -> str | None:
    if not isinstance(a, dict):
        return "artifact is not an object"
    if not isinstance(a.get("stored_path"), str) or not isinstance(a.get("sha256"), str):
        return "artifact lacks a stored_path or sha256"
    return None


class Case:
    def __init__(self, directory: Path, key: bytes | None = None, actor: str | None = None):
        self.dir = directory
        self.ledger = Ledger(directory / "ledger.jsonl", key=key, actor=actor)
        self.evidence_dir = directory / "evidence"

    @property
    def id(self) -> str:
        return self.dir.name

    def info(self) -> dict:
        for entry in self.ledger.entries():
            if entry.get("kind") == "case.create" and isinstance(entry.get("payload"), dict):
                return entry["payload"]
        return {"id": self.id}

    def replay(self) -> tuple[dict[str, Event], list[str]]:
        """Rebuild every event's current state from the ledger.

        Entries that can't apply (wrong shape, an update to an event that doesn't
        exist, a duplicate event id, an unknown field) are skipped and reported
        rather than aborting, so one bad line can't make the whole case unreadable.

        A field is only ever "confirmed" by an `event.update` entry (a recorded
        correction with a reason). Creation entries can carry machine-extracted
        values, but a claim of confirmation made at creation is ignored.
        """
        events: dict[str, Event] = {}
        problems: list[str] = []
        for entry in self.ledger.entries():
            seq, kind, p = entry.get("seq"), entry.get("kind"), entry.get("payload")
            if kind == "case.create":
                continue
            if kind == "event.add":
                if bad := _event_payload_problem(p):
                    problems.append(f"entry {seq}: event.add ignored ({bad})")
                    continue
                if p["id"] in events:
                    problems.append(f"entry {seq}: duplicate event id {p['id']} (ignored)")
                    continue
                p = copy.deepcopy(p)  # cached entries are shared; never mutate them
                origin = p.get("origin") or {}
                claimed = sorted(k for k, v in origin.items() if v != "extracted")
                if claimed:
                    problems.append(f"entry {seq}: confirmation claimed at creation for "
                                    f"{', '.join(claimed)} (ignored; confirm with an edit)")
                p["origin"] = {k: v for k, v in origin.items() if v == "extracted"}
                p["artifacts"] = []
                events[p["id"]] = Event.from_dict(p)
            elif kind in ("event.update", "artifact.link"):
                if not isinstance(p, dict):
                    problems.append(f"entry {seq}: {kind} ignored (payload is not an object)")
                    continue
                target = p.get("id") if kind == "event.update" else p.get("event_id")
                if not isinstance(target, str) or target not in events:
                    problems.append(f"entry {seq}: {kind} refers to unknown event {target} (ignored)")
                    continue
                ev = events[target]
                if kind == "artifact.link":
                    if bad := _artifact_problem(p.get("artifact")):
                        problems.append(f"entry {seq}: artifact.link ignored ({bad})")
                        continue
                    ev.artifacts.append(copy.deepcopy(p["artifact"]))
                    continue
                changes = p.get("changes")
                if not isinstance(changes, dict):
                    problems.append(f"entry {seq}: event.update ignored (changes is not an object)")
                    continue
                for name, value in changes.items():
                    if name not in EDITABLE:
                        problems.append(f"entry {seq}: update to non-editable field '{name}' (ignored)")
                    elif not isinstance(value, str):
                        problems.append(f"entry {seq}: update to '{name}' is not text (ignored)")
                    else:
                        setattr(ev, name, value)
                        ev.origin[name] = "confirmed"
            else:
                problems.append(f"entry {seq}: unknown entry kind '{kind}' (ignored)")
        return events, problems

    def events(self) -> dict[str, Event]:
        return self.replay()[0]

    def next_event_id(self) -> str:
        # One past the highest id ever added, so ids are never reused even if
        # the ledger contains out-of-order or hand-made entries.
        highest = 0
        for e in self.ledger.entries():
            p = e.get("payload")
            if e.get("kind") == "event.add" and isinstance(p, dict):
                m = re.fullmatch(r"EVT-(\d+)", str(p.get("id", "")))
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
        with self.ledger.locked():
            self.ledger.append("event.add", payload)
            for artifact in artifacts:
                self.ledger.append("artifact.link", {"event_id": event.id, "artifact": artifact})
        return event

    def add_new_event(self, fields_: dict, *artifacts: dict) -> Event:
        """Allocate the next id and add the event in one locked step, so two writers can't share an id."""
        with self.ledger.locked():
            ev = Event.from_dict(dict(fields_, id=self.next_event_id()))
            return self.add_event(ev, *artifacts)

    def update_event(self, event_id: str, changes: dict, reason: str) -> None:
        with self.ledger.locked():
            if event_id not in self.events():
                raise KeyError(f"No event {event_id} in case {self.id}")
            self.ledger.append("event.update", {"id": event_id, "changes": changes, "reason": reason})

    def link_artifact(self, event_id: str, src: Path) -> dict:
        if event_id not in self.events():
            raise KeyError(f"No event {event_id} in case {self.id}")
        artifact = self.store_artifact(src)
        self.ledger.append("artifact.link", {"event_id": event_id, "artifact": artifact})
        return artifact

    def entries_after(self, anchor: str) -> int | None:
        """How many entries were appended after an anchored head (None if it isn't in the ledger)."""
        pos = self.ledger.position(anchor)
        return None if pos is None else len(self.ledger.entries(fresh=True)) - pos

    def verify(self, expect_head: str | None = None) -> list[str]:
        """Check the ledger chain (and signatures, with a key), every recorded evidence file,
        and the evidence folder.

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
                rel = art["stored_path"]
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
                elif sha256_file(path) != art["sha256"]:
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


# Starts and ends with a letter or digit (Windows silently drops a trailing '.',
# which would let "x." and "x" name the same folder).
CASE_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9_-])?")
# Windows device names can't be used as folder names, with or without an extension.
RESERVED = re.compile(r"(?i)(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?")


def valid_case_id(case_id: str) -> bool:
    return bool(CASE_ID.fullmatch(case_id)) and ".." not in case_id and not RESERVED.fullmatch(case_id)


class Workspace:
    def __init__(self, root: Path, key: bytes | None = None, actor: str | None = None):
        self.root = root
        self.key = key
        self.actor = actor

    def _case(self, directory: Path) -> Case:
        return Case(directory, key=self.key, actor=self.actor)

    def _case_dir(self, case_id: str) -> Path:
        """Map a case id to its folder, refusing anything that could leave the workspace or alias another case."""
        if not valid_case_id(case_id):
            raise ValueError("Case id must start and end with a letter or digit, contain only letters, "
                             "digits, '.', '_' and '-' (no '..'), and not be a reserved device name")
        directory = self.root / case_id
        root = self.root.resolve()
        resolved = directory.resolve()
        if resolved.parent != root or resolved.name != case_id:
            raise ValueError(f"Case id '{case_id}' does not resolve to its own folder inside {root}")
        return directory

    def create_case(self, case_id: str, title: str, subject: str = "", institution: str = "") -> Case:
        directory = self._case_dir(case_id)
        if (directory / "ledger.jsonl").exists():
            raise FileExistsError(f"Case {case_id} already exists at {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        case = self._case(directory)
        case.ledger.append("case.create", {
            "id": case_id, "title": title, "subject": subject,
            "institution": institution, "created_at": now_iso(),
        })
        return case

    def open_case(self, case_id: str) -> Case:
        directory = self._case_dir(case_id)
        if not (directory / "ledger.jsonl").exists():
            raise FileNotFoundError(f"No case '{case_id}' under {self.root}")
        return self._case(directory)

    def list_cases(self) -> list[Case]:
        if not self.root.exists():
            return []
        return [self._case(d) for d in sorted(self.root.iterdir())
                if valid_case_id(d.name) and (d / "ledger.jsonl").exists()]
