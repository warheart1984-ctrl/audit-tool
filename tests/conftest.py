from __future__ import annotations

import pytest

from audit_tool.cli import main
from audit_tool.store import Workspace


@pytest.fixture
def ws(tmp_path):
    return Workspace(tmp_path / "cases")


@pytest.fixture
def cli(tmp_path, capsys):
    """Run the real CLI against a temp workspace; returns (exit code, stdout + stderr)."""

    def run(*args: str) -> tuple[int, str]:
        code = 0
        try:
            main(["--root", str(tmp_path / "cases"), *args])
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        out = capsys.readouterr()
        return code, out.out + out.err

    return run
