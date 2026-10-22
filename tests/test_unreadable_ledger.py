"""A ledger that can't be parsed is an integrity failure (exit 2), never a crash
(PR #1, Low finding). A JSON escape like \\ud800 decodes to a lone surrogate,
which has no UTF-8 form and can't be hashed; before, every command exited 1
with a codec error and `list` stopped at that case."""

from __future__ import annotations

import pytest

from audit_tool.ledger import Ledger


def _inject_surrogate(path):
    text = path.read_text(encoding="utf-8")
    assert '"title": "t"' in text
    path.write_text(text.replace('"title": "t"', '"title": "t\\ud800"', 1), encoding="utf-8")


def test_lone_surrogate_is_reported_by_verify(ws):
    case = ws.create_case("c", "t")
    _inject_surrogate(case.ledger.path)
    problems = case.verify()
    assert len(problems) == 1 and "lone surrogate" in problems[0]
    assert Ledger(case.ledger.path).verify() == problems


def test_invalid_utf8_bytes_are_reported_by_verify(ws):
    case = ws.create_case("c", "t")
    with case.ledger.path.open("ab") as fh:
        fh.write(b'{"seq": 2, "kind": "\xff\xfe"}\n')
    problems = case.verify()
    assert len(problems) == 1 and "not valid UTF-8" in problems[0]


@pytest.mark.parametrize("args", [("verify", "b"), ("check", "b"), ("show", "b", "EVT-0001"),
                                  ("report", "b"), ("head", "b")])
def test_every_command_exits_2_on_a_lone_surrogate(cli, tmp_path, args):
    cli("new", "b", "--title", "t")
    _inject_surrogate(tmp_path / "cases" / "b" / "ledger.jsonl")
    code, out = cli(*args)
    assert code == 2, out
    assert "INTEGRITY FAILED" in out and "lone surrogate" in out
    assert "codec can't encode" not in out


def test_list_continues_past_an_unreadable_case(cli, tmp_path):
    for case_id in ("a", "b", "c"):
        cli("new", case_id, "--title", "t")
    _inject_surrogate(tmp_path / "cases" / "b" / "ledger.jsonl")
    code, out = cli("list")
    lines = out.splitlines()
    assert lines[0].startswith("a ") and "INTEGRITY FAILED" not in lines[0]
    assert lines[1].startswith("b ") and "INTEGRITY FAILED" in lines[1]
    assert lines[2].startswith("c ")
