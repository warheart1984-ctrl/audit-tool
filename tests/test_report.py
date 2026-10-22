"""Evidence text must render as text, never as report structure (F4)."""

from __future__ import annotations

from audit_tool.models import Event
from audit_tool.report import render_markdown


def _report(ws, **fields):
    case = ws.create_case("c", fields.pop("title", "t"))
    case.add_event(Event(id="EVT-0001", decision=fields.pop("decision", "Denied"), **fields))
    return render_markdown(case)


def _outside_fences(md: str) -> list[str]:
    """Lines Markdown would render as structure. Fenced blocks are literal text, so skip them."""
    out, fence = [], None
    for line in md.splitlines():
        stripped = line.lstrip()
        if fence is None and stripped.startswith("```"):
            fence = stripped[: len(stripped) - len(stripped.lstrip("`"))]
        elif fence is not None and stripped == fence:
            fence = None
        elif fence is None:
            out.append(line)
    assert fence is None, "unterminated code block"
    return out


def test_backtick_fence_in_evidence_cannot_break_out(ws):
    md = _report(ws, reason="x\n```\n\n## INJECTED HEADING\n\n```text")
    assert not any("INJECTED" in line for line in _outside_fences(md))
    # The block that holds the reason uses a longer fence than the evidence contains.
    assert "````text" in md


def test_links_in_evidence_are_not_rendered_as_links(ws):
    md = _report(ws, decision="Denied [proof](https://evil.example)")
    rendered = "\n".join(_outside_fences(md))
    assert "[proof](https://evil.example)" not in rendered
    assert "\\[proof\\]\\(https://evil.example\\)" in rendered


def test_newlines_and_pipes_cannot_add_table_rows_or_headings(ws):
    md = _report(ws, decision="Denied |\n# FAKE FINDING | high |", title="Case\n# Not a heading")
    rendered = _outside_fences(md)
    assert not any(line.lstrip().startswith("# FAKE") or line.lstrip().startswith("# Not") for line in rendered)
    assert not any("| high |" in line and "FAKE" in line and "\\|" not in line for line in rendered)


def test_report_states_the_integrity_guarantee_accurately(ws):
    md = _report(ws)
    assert "Ledger anchor at the time of this report" in md
    assert "any later change to a recorded entry can be detected" not in md
    assert "only detected against a head hash saved somewhere else" in md
