# checks/extra_checks.py
# ---------------------------------------------------------------------------
# Extra Code-Quality Rules for test_code_quality_gate.py
#
#  CS001  circular_import        – two-way import between modules
#  CS002  unused_import          – import never referenced
#  CS003  magic_number           – numeric literals outside {-1,-1,0,1} in code
#  CS004  hardcoded_secret       – suspicious secrets / tokens in source
#  CS005  todo_comment           – TODO / FIXME left in code
#  CS006  large_class            – class with >10 methods
#  CS007  deep_inheritance       – class with >2 base classes
#  CS008  redundant_pass         – lone pass when code already present
#  CS009  inefficient_loop       – range(len(seq)) index loops
#  CS010  duplicate_import_alias – same module imported twice with different alias
# ---------------------------------------------------------------------------

from __future__ import annotations

import ast
import sys
from collections import defaultdict
from pathlib import Path
from typing import List, Sequence, Tuple

# Update import path to use the proper path for bs_common
sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))
from bs_common import CodeCheck, suppressed

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

NUM_OK = {-1, 0, 1}


def _find_imports(tree: ast.AST):
    """Return list[(alias name, module path, lineno)]"""
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                yield a.asname or a.name, a.name, n.lineno
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                yield a.asname or a.name, f"{n.module}.{a.name}", n.lineno


def _module_path(mod: str, start: Path) -> Path | None:
    """Best-effort resolve to *.py file inside project."""
    try:
        spec = __import__(mod.split(".", 1)[0])
        file = Path(spec.__file__ or "")
        if file.suffix == ".py":
            return file.resolve()
    except Exception:
        pass
    # Relative import in same package
    maybe = (start.parent / (mod.replace(".", "/") + ".py")).resolve()
    return maybe if maybe.is_file() else None


# ---------------------------------------------------------------------------
# Custom check classes
# ---------------------------------------------------------------------------


class CircularImport(CodeCheck):
    """Detect simple two-file circular import."""

    code = "CS001"

    def check(
        self, node: ast.AST, src: List[str], cfg
    ) -> Sequence[Tuple[int, str, str]]:
        if not isinstance(node, ast.Module):
            return ()
        here = cfg.current_file  # injected later
        offenders = []
        for _, mod, ln in _find_imports(node):
            tgt = _module_path(mod, here)
            if tgt and tgt != here:
                try:
                    other_src = tgt.read_text(encoding="utf-8")
                    if (
                        f"import {here.stem}" in other_src
                        or f"from {here.stem} import" in other_src
                    ):
                        if not suppressed(src[ln - 1], self.code):
                            offenders.append(
                                (ln, f"circular import with {tgt.name}", self.code)
                            )
                except (OSError, UnicodeDecodeError):
                    pass
        return offenders


class UnusedImport(CodeCheck):
    code = "CS002"

    def check(self, node, src, cfg):
        if not isinstance(node, ast.Module):
            return ()
        assigned = {}
        used = set()
        for n in ast.walk(node):
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    assigned[a.asname or a.name] = n.lineno
            elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                used.add(n.id)
        return [
            (ln, f"unused import '{name}'", self.code)
            for name, ln in assigned.items()
            if name not in used and not suppressed(src[ln - 1], self.code)
        ]


class MagicNumber(CodeCheck):
    code = "CS003"

    def check(self, node, src, cfg):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            if node.value not in NUM_OK and not suppressed(
                src[node.lineno - 1], self.code
            ):
                return ((node.lineno, f"magic number {node.value}", self.code),)
        return ()


class HardcodedSecret(CodeCheck):
    code = "CS004"
    _KEYS = {"password", "passwd", "secret", "token", "apikey", "api_key"}

    def check(self, node, src, cfg):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id.lower() in self._KEYS:
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, str
                    ):
                        if len(node.value.value) > 12 and not suppressed(
                            src[node.lineno - 1], self.code
                        ):
                            return (
                                (
                                    node.lineno,
                                    f"hard-coded secret in '{t.id}'",
                                    self.code,
                                ),
                            )
        return ()


class TodoComment(CodeCheck):
    code = "CS005"

    def check(self, node, src, cfg):
        if isinstance(node, ast.Module):
            return [
                (i + 1, "TODO/FIXME present", self.code)
                for i, l in enumerate(src)
                if ("todo" in l.lower() or "fixme" in l.lower())
                and not suppressed(l, self.code)
            ]
        return ()


class LargeClass(CodeCheck):
    code = "CS006"

    def check(self, node, src, cfg):
        if isinstance(node, ast.ClassDef):
            methods = [
                n
                for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if len(methods) > 10 and not suppressed(src[node.lineno - 1], self.code):
                return (
                    (
                        node.lineno,
                        f"{node.name}: {len(methods)} methods (>10)",
                        self.code,
                    ),
                )
        return ()


class DeepInheritance(CodeCheck):
    code = "CS007"

    def check(self, node, src, cfg):
        if isinstance(node, ast.ClassDef) and len(node.bases) > 2:
            if not suppressed(src[node.lineno - 1], self.code):
                return (
                    (
                        node.lineno,
                        f"{node.name}: deep inheritance ({len(node.bases)} bases)",
                        self.code,
                    ),
                )
        return ()


class RedundantPass(CodeCheck):
    code = "CS008"

    def check(self, node, src, cfg):
        if isinstance(node, ast.Pass):
            # Check neighbouring lines for real code
            ln = node.lineno
            before = src[ln - 2].strip() if ln >= 2 else ""
            after = src[ln].strip() if ln < len(src) else ""
            if (before or after) and not suppressed(src[ln - 1], self.code):
                return ((ln, "redundant pass statement", self.code),)
        return ()


class InefficientLoop(CodeCheck):
    code = "CS009"

    def check(self, node, src, cfg):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call):
            fn = node.iter.func
            if isinstance(fn, ast.Name) and fn.id == "range" and node.iter.args:
                arg0 = node.iter.args[0]
                if (
                    isinstance(arg0, ast.Call)
                    and isinstance(arg0.func, ast.Name)
                    and arg0.func.id == "len"
                ):
                    if not suppressed(src[node.lineno - 1], self.code):
                        return (
                            (
                                node.lineno,
                                "loop over range(len(seq)) – use enumerate",
                                self.code,
                            ),
                        )
        return ()


class DuplicateImportAlias(CodeCheck):
    code = "CS010"

    def check(self, node, src, cfg):
        if not isinstance(node, ast.Module):
            return ()
        alias_map = defaultdict(set)  # module -> {alias}
        offenders = []
        for alias, mod, ln in _find_imports(node):
            if alias in alias_map[mod] and not suppressed(src[ln - 1], self.code):
                offenders.append((ln, f"duplicate import alias for {mod}", self.code))
            alias_map[mod].add(alias)
        return offenders


# ---------------------------------------------------------------------------
# Hook for Config to provide current file to checks needing context
# ---------------------------------------------------------------------------


# Define a function to patch the Analyzer class when it is available
def patch_analyzer():
    try:
        from tests.test_code_quality_gate import Analyzer

        # Store the original run method
        orig_run = Analyzer.run

        # Create a new run method that sets the current_file attribute on cfg
        def run_with_path(self):
            # Inject current file pointer so checks like CircularImport can resolve paths
            setattr(self.cfg, "current_file", self.path)
            return orig_run(self)

        # Apply the patch
        Analyzer.run = run_with_path

    except ImportError:
        # If we can't import Analyzer yet, we'll try again later
        pass
