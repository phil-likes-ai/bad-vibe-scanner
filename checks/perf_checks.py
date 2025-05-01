# checks/perf_checks.py
# ---------------------------------------------------------------------------
# Performance / Safety – Supplemental Code-Quality Rules
#
#  CS011  no_context_manager_open   – open() without a with-statement
#  CS012  empty_except_pass         – except-block that silently `pass`es
#  CS013  slow_list_concat          – += list growth inside loop
#  CS014  meaningless_op            – *1 or %1 or +0 arithmetic
#  CS015  dict_key_lookup_loop      – for k in d: d[k] anti-pattern
#  CS016  large_literal_list        – list/tuple literal with >100 items
#  CS017  unbalanced_thread_start   – threading.Thread(...).start() w/o join()
#  CS018  resource_not_closed       – sqlite3 / socket created w/o close/with
#  CS019  redundant_else_return     – else: return immediately after return path
#  CS020  kwargs_unused             – function has **kwargs but never references
# ---------------------------------------------------------------------------

from __future__ import annotations

import ast
import sys
import threading
from collections import defaultdict
from pathlib import Path
from typing import List, Sequence, Tuple

# Update import path to use the proper path for bs_common
sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from bs_common import CodeCheck, suppressed, set_parents


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _walk_calls(node: ast.AST, fn_names: set[str]):
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in fn_names
        ):
            yield n


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------


class NoContextManagerOpen(CodeCheck):
    code = "CS011"

    def check(self, node, src, cfg):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        ):
            # ensure our parent is a With node
            for p in ast.walk(node.parent):  # type: ignore[attr-defined]
                if isinstance(p, ast.With) and node in ast.walk(p):
                    break
            else:
                if not suppressed(src[node.lineno - 1], self.code):
                    return ((node.lineno, "open() without context-manager", self.code),)
        return ()


class EmptyExceptPass(CodeCheck):
    code = "CS012"

    def check(self, node, src, cfg):
        if isinstance(node, ast.ExceptHandler):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                if not suppressed(src[node.lineno - 1], self.code):
                    return (
                        (node.lineno, "except … : pass  (swallows errors)", self.code),
                    )
        return ()


class SlowListConcat(CodeCheck):
    code = "CS013"

    def check(self, node, src, cfg):
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            if isinstance(node.target, ast.Name) and isinstance(node.value, ast.Name):
                targ, val = node.target.id, node.value.id
                if targ == val and not suppressed(src[node.lineno - 1], self.code):
                    return (
                        (
                            node.lineno,
                            "list += growth inside loop – use append/extend",
                            self.code,
                        ),
                    )
        return ()


class MeaninglessOp(CodeCheck):
    code = "CS014"
    _OPS = {(ast.Mult, 1), (ast.Mod, 1), (ast.Add, 0), (ast.Sub, 0)}

    def check(self, node, src, cfg):
        if isinstance(node, ast.BinOp) and isinstance(node.right, ast.Constant):
            for op_cls, val in self._OPS:
                if isinstance(node.op, op_cls) and node.right.value == val:
                    if not suppressed(src[node.lineno - 1], self.code):
                        return (
                            (
                                node.lineno,
                                "ineffective arithmetic operation",
                                self.code,
                            ),
                        )
        return ()


class DictKeyLookupLoop(CodeCheck):
    code = "CS015"

    def check(self, node, src, cfg):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            fn = node.iter.func
            if isinstance(fn, ast.Attribute) and fn.attr == "keys":
                if isinstance(fn.value, ast.Name):
                    dname = fn.value.id
                    # see if body loads dname[...] pattern
                    for n in ast.walk(node):
                        if (
                            isinstance(n, ast.Subscript)
                            and isinstance(n.value, ast.Name)
                            and n.value.id == dname
                        ):
                            if not suppressed(src[node.lineno - 1], self.code):
                                return (
                                    (
                                        node.lineno,
                                        f"iterate dict keys then index '{dname}' – use .items()",
                                        self.code,
                                    ),
                                )
        return ()


class LargeLiteralList(CodeCheck):
    code = "CS016"

    def check(self, node, src, cfg):
        if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) > 100:
            if not suppressed(src[node.lineno - 1], self.code):
                return (
                    (
                        node.lineno,
                        f"huge literal with {len(node.elts)} items",
                        self.code,
                    ),
                )
        return ()


class UnbalancedThreadStart(CodeCheck):
    code = "CS017"

    def check(self, node, src, cfg):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "start":
                if isinstance(node.func.value, ast.Call) and isinstance(
                    node.func.value.func, ast.Name
                ):
                    if node.func.value.func.id == "Thread":  # threading.Thread(...)
                        # naive heuristic: look for .join() in same scope
                        parent = node
                        while parent and not isinstance(
                            parent, (ast.FunctionDef, ast.Module)
                        ):
                            parent = getattr(parent, "parent", None)
                        if parent and not any(
                            isinstance(n, ast.Call)
                            and isinstance(n.func, ast.Attribute)
                            and n.func.attr == "join"
                            for n in ast.walk(parent)
                        ):
                            if not suppressed(src[node.lineno - 1], self.code):
                                return (
                                    (
                                        node.lineno,
                                        "thread started without join()",
                                        self.code,
                                    ),
                                )
        return ()


class ResourceNotClosed(CodeCheck):
    code = "CS018"
    _RES = {"socket", "sqlite3"}

    def check(self, node, src, cfg):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "connect" and isinstance(node.func.value, ast.Name):
                if node.func.value.id in self._RES and not suppressed(
                    src[node.lineno - 1], self.code
                ):
                    return (
                        (
                            node.lineno,
                            f"{node.func.value.id}.connect() without context/close",
                            self.code,
                        ),
                    )
        return ()


class RedundantElseReturn(CodeCheck):
    code = "CS019"

    def check(self, node, src, cfg):
        if isinstance(node, ast.If) and node.orelse:
            if any(isinstance(n, ast.Return) for n in node.body):
                if any(isinstance(n, ast.Return) for n in node.orelse):
                    if not suppressed(src[node.lineno - 1], self.code):
                        return (
                            (node.lineno, "redundant else after return", self.code),
                        )
        return ()


class KwargsUnused(CodeCheck):
    code = "CS020"

    def check(self, node, src, cfg):
        if isinstance(node, ast.FunctionDef) and node.args.kwarg:
            name = node.args.kwarg.arg
            used = any(
                isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
                for n in ast.walk(node)
            )
            if not used and not suppressed(src[node.lineno - 1], self.code):
                return ((node.lineno, f"**{name} collected but never used", self.code),)
        return ()


# ---------------------------------------------------------------------------
# Link parents for upward traversal & patch Analyzer
# ---------------------------------------------------------------------------


# Define a function to patch the Analyzer class when it is available
def patch_analyzer():
    try:
        from tests.test_code_quality_gate import Analyzer

        # Modify the visit method to set parent nodes
        orig_visit = Analyzer.visit

        def visit_with_parent(self, node):
            set_parents(node)
            return orig_visit(self, node)

        # Apply the patch
        Analyzer.visit = visit_with_parent

    except ImportError:
        # If we can't import Analyzer yet, we'll try again later
        pass
