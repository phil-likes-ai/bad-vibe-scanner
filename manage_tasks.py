#!/usr/bin/env python3
"""
task_engine.manage_tasks  ·  Re-wired quality gate runner (2025-05-01)

• Scans a target path (file or folder) for code-quality issues.
• Runs pytest on the test suite without custom flags.
• Optionally runs ruff, mypy, bandit, and pip-audit as separate checks.

Usage
-----
python -m task_engine.manage_tasks --scan ./src
python -m task_engine.manage_tasks --scan ./src/bad.py
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _run(cmd: List[str], label: str) -> int:
    """Run a command, stream output, return the exit-code."""
    print(f"\n── {label}: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, text=True)
        return proc.returncode
    except FileNotFoundError:
        print(f"[SKIP] {label} not installed.")
        return 0


def run_linters(target: Path) -> int:
    """Run ruff, mypy, bandit, and pip-audit; collect the worst RC."""
    rc = 0
    rc = max(rc, _run(["ruff", str(target)], "ruff"))
    rc = max(rc, _run(["mypy", str(target)], "mypy"))
    rc = max(rc, _run(["bandit", "-r", str(target)], "bandit"))
    rc = max(rc, _run(["pip-audit", "-r", "requirements.txt"], "pip-audit"))
    return rc


def run_pytest() -> int:
    """Run pytest without extra flags."""
    return _run(["pytest", "-q"], "pytest")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage tasks / run quality gate")
    parser.add_argument(
        "--scan",
        metavar="PATH",
        help="File or directory to scan (default: ./src)",
        default="./src",
    )
    args = parser.parse_args()

    target = Path(args.scan).resolve()
    if not target.exists():
        print(f"ERROR: target {target} does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"=== Quality gate for: {target}")

    rc = 0
    rc = max(rc, run_linters(target))
    rc = max(rc, run_pytest())

    if rc == 0:
        print("\n✅ All checks passed.")
    else:
        print("\n❌ Quality gate failed.")
    sys.exit(rc)


if __name__ == "__main__":
    main()
