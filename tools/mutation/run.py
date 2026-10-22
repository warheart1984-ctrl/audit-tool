"""Mutation run: does the test suite catch known defects?

Copies the repo to a temp folder, plants one defect at a time (see mutants.py),
and runs the full suite. A mutant is KILLED if the suite fails and SURVIVES if it
passes. A survivor is a guarantee the tests don't actually enforce. The checkout
you run this from is never modified.

    python tools/mutation/run.py              # all mutants (about 15 minutes)
    python tools/mutation/run.py L1 S5 R2     # just these

Exit code: 0 if every applicable mutant was killed, 1 otherwise.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants import MUTANTS, PLATFORM_ONLY  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SUITE_TIMEOUT = 600


def fresh_copy(work: Path) -> None:
    shutil.copytree(REPO, work, ignore=shutil.ignore_patterns(
        ".git", "cases", "__pycache__", "build", "*.egg-info", "fixtures", "*.jpg", "*.jpeg", "*.png", "*.pdf", "*.eml"))
    # Example files the tests may use are small; copy them back explicitly.
    shutil.copytree(REPO / "examples", work / "examples", dirs_exist_ok=True)


def run_suite(work: Path) -> tuple[bool, str]:
    r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                       cwd=work, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=SUITE_TIMEOUT)
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    first_fail = next((l for l in lines if l.startswith(("FAILED", "ERROR"))), "")
    return r.returncode == 0, (first_fail or (lines[-1] if lines else "(no output)"))[:160]


def applies_here(mid: str) -> bool:
    want = PLATFORM_ONLY.get(mid)
    return want is None or want == ("win32" if sys.platform == "win32" else "posix")


def main(selected: list[str]) -> int:
    mutants = [m for m in MUTANTS if not selected or m[0] in selected]
    unknown = set(selected) - {m[0] for m in MUTANTS}
    if unknown:
        sys.exit(f"unknown mutant id(s): {', '.join(sorted(unknown))}")

    with tempfile.TemporaryDirectory(prefix="audit-mutation-") as tmp:
        work = Path(tmp) / "repo"
        fresh_copy(work)
        ok, summary = run_suite(work)
        print(f"BASELINE {'pass' if ok else 'FAIL'}: {summary}", flush=True)
        if not ok:
            print("The unmodified suite must pass before mutants mean anything.")
            return 1

        results = []
        for mid, fname, old, new, guarantee in mutants:
            if not applies_here(mid):
                print(f"{mid:4} n/a      ({PLATFORM_ONLY[mid]} only)  {guarantee}", flush=True)
                continue
            path = work / "audit_tool" / fname
            src = path.read_text(encoding="utf-8")
            if src.count(old) != 1:
                print(f"{mid:4} STALE    target text found {src.count(old)} times; update mutants.py  {guarantee}",
                      flush=True)
                results.append((mid, "STALE", guarantee))
                continue
            path.write_text(src.replace(old, new), encoding="utf-8")
            start = time.monotonic()
            try:
                survived, detail = run_suite(work)
            except subprocess.TimeoutExpired:
                survived, detail = False, "suite timed out (counted as killed)"
            finally:
                path.write_text(src, encoding="utf-8")
            status = "SURVIVED" if survived else "killed"
            print(f"{mid:4} {status:8} {time.monotonic() - start:5.1f}s  {guarantee}  | {detail}", flush=True)
            results.append((mid, status, guarantee))

    killed = [r for r in results if r[1] == "killed"]
    bad = [r for r in results if r[1] != "killed"]
    total = len(results)
    print(f"\nRESULT: {len(killed)}/{total} killed"
          + (f" ({100 * len(killed) / total:.0f}%)" if total else "")
          + ("; not killed: " + ", ".join(f"{m} {s} ({g})" for m, s, g in bad) if bad else "; no survivors"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
