# bs_common.py - Common code for the Bad Vibe Scanner
# This file contains shared code to avoid circular imports

from __future__ import annotations

import ast
from typing import List, Sequence, Tuple


# ── suppression check  (# noqa & codes) ──────────────────────────────────────
def suppressed(line: str, code: str) -> bool:
    if "# noqa" not in line:
        return False
    if line.strip().endswith("# noqa"):
        return True
    return f"# noqa: {code}" in line


# ── CodeCheck base class  (every rule returns (lineno,msg,code)) ─────────────
class CodeCheck:
    code: str  # e.g. BS001

    def check(
        self, node: ast.AST, src: List[str], cfg
    ) -> Sequence[Tuple[int, str, str]]:
        return ()


# ── Set parents for AST traversal ────────────────────────────────────────────
def set_parents(tree):
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            c.parent = n  # type: ignore[attr-defined]
