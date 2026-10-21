"""Data model for cases, events (decisions) and evidence artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields

TRISTATE = ("yes", "no", "unknown")
EVIDENCE_STATUS = ("verified", "unverified", "missing")
SOURCE_TYPES = (
    "email",
    "letter",
    "transcript",
    "chat",
    "transaction",
    "screenshot",
    "note",
    "other",
)

# Fields a person may set or correct with `audit edit`.
EDITABLE = (
    "source_type", "source", "timestamp", "sender", "recipient", "subject",
    "request", "decision", "status_code", "reason", "policy_cited",
    "legal_basis", "automated", "human_involved", "notice_provided",
    "appeal_path", "reproducible", "supporting_evidence", "outcome",
    "evidence_status", "notes",
)


@dataclass
class Artifact:
    sha256: str
    stored_path: str  # relative to the case directory
    original_name: str
    size: int
    added_at: str


@dataclass
class Event:
    """One recorded decision or action, e.g. a rejected email or a declined payment."""

    id: str
    source_type: str = "other"
    source: str = ""  # system or institution that produced the artifact
    timestamp: str = ""
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    request: str = ""  # what the customer asked for / attempted
    decision: str = ""  # what the system did
    status_code: str = ""
    reason: str = ""  # reason given by the institution
    policy_cited: str = ""
    legal_basis: str = ""
    automated: str = "unknown"
    human_involved: str = "unknown"
    notice_provided: str = "unknown"
    appeal_path: str = ""
    reproducible: str = "unknown"
    supporting_evidence: str = ""  # evidence the institution gave for the decision
    outcome: str = ""
    evidence_status: str = "unverified"  # status of *our* proof that the event happened
    notes: str = ""
    artifacts: list[dict] = field(default_factory=list)
    # field name -> "extracted" (heuristic guess) or "confirmed" (set by a person)
    origin: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Event":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)


def validate_field(name: str, value: str) -> str:
    if name not in EDITABLE:
        raise ValueError(f"'{name}' is not an editable field. Choose from: {', '.join(EDITABLE)}")
    value = value.strip()
    if name in ("automated", "human_involved", "notice_provided", "reproducible"):
        value = value.lower()
        if value not in TRISTATE:
            raise ValueError(f"{name} must be one of {TRISTATE}")
    if name == "evidence_status":
        value = value.lower()
        if value not in EVIDENCE_STATUS:
            raise ValueError(f"evidence_status must be one of {EVIDENCE_STATUS}")
    if name == "source_type":
        value = value.lower()
        if value not in SOURCE_TYPES:
            raise ValueError(f"source_type must be one of {SOURCE_TYPES}")
    return value
