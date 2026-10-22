"""Owner-only file permissions for case data.

Case folders hold bank letters, statements and IDs. On Linux/macOS they are
created 0700 (folders) / 0600 (files). On Windows, folders otherwise inherit
whatever the drive grants (often "Authenticated Users: Modify"), so inheritance
is removed and only the current user and SYSTEM are granted access; files
created inside then inherit that. (Python 3.12.4+ also grants Administrators
when it creates a 0700 folder on Windows; administrators can take ownership of
any file regardless, so that adds no access they couldn't get.)

This limits other accounts on the same machine. It is not encryption: use full
disk encryption (BitLocker, FileVault, LUKS) to protect the data at rest.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

SYSTEM_SID = "S-1-5-18"


def _system_tool(name: str) -> str:
    # Absolute path: a same-named program earlier on PATH (Git for Windows ships
    # a POSIX `whoami`) must not be run instead.
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


def _current_user_sid() -> str:
    out = subprocess.run([_system_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip().split(",")[-1].strip().strip('"')


def restrict_dir(path: Path) -> None:
    """Make a folder accessible to its owner only (and SYSTEM on Windows)."""
    if sys.platform == "win32":
        sid = _current_user_sid()
        subprocess.run(
            [_system_tool("icacls.exe"), str(path), "/inheritance:r",
             "/grant:r", f"*{sid}:(OI)(CI)F", f"*{SYSTEM_SID}:(OI)(CI)F"],
            capture_output=True, text=True, check=True)
        return
    os.chmod(path, 0o700)


def restrict_file(path: Path) -> None:
    """Owner-only access to a single file (used for private keys)."""
    if sys.platform == "win32":
        sid = _current_user_sid()
        subprocess.run([_system_tool("icacls.exe"), str(path), "/inheritance:r", "/grant:r", f"*{sid}:F", f"*{SYSTEM_SID}:F"],
                       capture_output=True, text=True, check=True)
        return
    os.chmod(path, 0o600)


def restrict_tree(path: Path) -> None:
    """Tighten an existing case folder and everything already in it."""
    restrict_dir(path)
    if sys.platform == "win32":
        # Children created before the folder was locked down may have their own ACLs.
        subprocess.run([_system_tool("icacls.exe"), str(path / "*"), "/reset", "/t", "/c", "/q"], capture_output=True, text=True)
        return
    for p in path.rglob("*"):
        if p.is_symlink():
            continue
        os.chmod(p, 0o700 if p.is_dir() else 0o600)


def make_private_dir(path: Path) -> None:
    created = not path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created:
        restrict_dir(path)


def private_file_mode(path: Path) -> None:
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def loose_permissions(path: Path) -> list[str]:
    """Paths under `path` that other local accounts can access (POSIX only; [] on Windows)."""
    if sys.platform == "win32":
        return []
    out = []
    for p in [path, *path.rglob("*")]:
        if p.is_symlink():
            continue
        if stat.S_IMODE(p.stat().st_mode) & 0o077:
            out.append(str(p.relative_to(path.parent)))
    return out


def windows_acl_entries(path: Path) -> str:
    """Raw icacls output, for checks and tests."""
    return subprocess.run([_system_tool("icacls.exe"), str(path)], capture_output=True, text=True).stdout
