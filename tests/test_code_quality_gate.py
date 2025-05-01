# test_code_quality_gate.py
# NASA-inspired, single-file code-quality gate
#
# Major upgrades over v1.1
#  • pluggable checks/ directory (dynamic import)
#  • dynamic pytest test-generation (one test per file × check)
#  • suppression token  # noqa: BS123
#  • end_lineno fallback for <3.8 interpreters
#  • no global CFG; Config flows explicitly
#
#   Built-in suppression codes
#     BS001  function_length
#     BS002  assertion_density
#     BS003  mutable_default
#     BS004  mixed_return
#     BS005  parameter_validation
#     BS006  prohibited_compare
#     BS007  nesting_depth
#     BS008  wildcard_import
#     BS009  exec_eval
#     BS010  dead_if
#     BS011  unused_local
#     BS012  max_args
#     BS013  bare_except
#     BS014  forbidden_calls
#     BS015  global_nonlocal
#     BS016  long_lines
#     BS017  mixed_tabs_spaces
#
#   # noqa: BS004  ← suppress a specific rule on that line
#   # noqa        ← suppress every rule on that line
#
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import inspect
import json
import logging
import subprocess
import sys
import uuid
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pytest
import yaml

# ── logging ──────────────────────────────────────────────────────────────────
LOG = logging.getLogger("bs")
LOG.addHandler(logging.StreamHandler(sys.stdout))
LOG.setLevel(logging.INFO)


# ── configuration object ─────────────────────────────────────────────────────
class Config:
    strict: bool = False
    max_func_lines: int = 50
    max_nesting_depth: int = 3
    run_mypy: bool = False
    run_bandit: bool = False
    max_complexity: int = 10
    files: List[str] = ["."]
    checks: List[str] = ["all"]
    output: str = "text"
    use_ruff: bool = False
    format_check: bool = False
    run_audit: bool = False

    def load_yaml(self, path: Path) -> None:
        if path.exists():
            for k, v in (yaml.safe_load(path.read_text()) or {}).items():
                setattr(self, k, v)

    def load_ns(self, ns: argparse.Namespace) -> None:
        for f in (
            "strict",
            "max_func_lines",
            "max_nesting_depth",
            "run_mypy",
            "run_bandit",
            "max_complexity",
            "files",
            "output",
            "use_ruff",
            "format_check",
            "run_audit",
        ):
            v = getattr(ns, f, None)
            if v not in (None, []):
                setattr(self, f, v)
        if ns.checks:
            self.checks = ns.checks.split(",")

    @classmethod
    def from_pytest(cls, pytestconfig) -> Config:
        cfg = cls()
        for opt in (
            "strict",
            "max_func_lines",
            "max_nesting_depth",
            "run_mypy",
            "run_bandit",
            "max_complexity",
            "files",
            "output",
            "use_ruff",
            "format_check",
            "run_audit",
            "output_file",
        ):
            val = pytestconfig.getoption(f"--{opt}")
            if val is not None:
                setattr(cfg, opt, val)
        checks = pytestconfig.getoption("--checks")
        if checks:
            cfg.checks = checks.split(",")
        return cfg


# ── helper: line count fallback (end_lineno pre-3.8) ─────────────────────────
def node_length(node: ast.AST, src: str) -> int:
    if hasattr(node, "end_lineno") and getattr(node, "end_lineno"):
        return node.end_lineno - node.lineno + 1
    # fallback raw slice
    lines = src.splitlines()
    idx = node.lineno - 1
    return len(lines[idx : idx + max(1, len(getattr(node, "body", [])))])


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
        self, node: ast.AST, src: List[str], cfg: Config
    ) -> Sequence[Tuple[int, str, str]]:
        return ()


# ── built-in checks ──────────────────────────────────────────────────────────
class FunctionLength(CodeCheck):
    code = "BS001"

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ln = node_length(n, "\n".join(s))
            if ln > c.max_func_lines and not suppressed(s[n.lineno - 1], self.code):
                return (
                    (
                        n.lineno,
                        f"{n.name}: {ln} LOC (max {c.max_func_lines})",
                        self.code,
                    ),
                )
        return ()


class AssertionDensity(CodeCheck):
    code = "BS002"

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cnt = sum(isinstance(x, ast.Assert) for x in ast.walk(n))
            need = 2 if c.strict else 1
            if cnt < need and not suppressed(s[n.lineno - 1], self.code):
                return ((n.lineno, f"{n.name}: {cnt} asserts (min {need})", self.code),)
        return ()


class MutableDefault(CodeCheck):
    code = "BS003"
    mut = (ast.List, ast.Dict, ast.Set)

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in (n.args.defaults or []) + (n.args.kw_defaults or []):
                if isinstance(d, self.mut) and not suppressed(
                    s[n.lineno - 1], self.code
                ):
                    return ((n.lineno, f"{n.name}: mutable default arg", self.code),)
        return ()


class MixedReturn(CodeCheck):
    code = "BS004"

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            val = any(isinstance(r, ast.Return) and r.value for r in ast.walk(n))
            none = any(
                isinstance(r, ast.Return) and r.value is None for r in ast.walk(n)
            )
            if val and none and not suppressed(s[n.lineno - 1], self.code):
                return ((n.lineno, f"{n.name}: mixed return paths", self.code),)
        return ()


class ParamValidation(CodeCheck):
    code = "BS005"

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in n.args.args if a.arg not in ("self", "cls")]
            long = node_length(n, "\n".join(s)) > 3
            if params and (c.strict or long):
                for stmt in n.body[:5]:
                    if isinstance(stmt, (ast.Assert, ast.If)) and any(
                        isinstance(x, ast.Name) and x.id in params
                        for x in ast.walk(stmt)
                    ):
                        return ()
                if not suppressed(s[n.lineno - 1], self.code):
                    return (
                        (n.lineno, f"{n.name}: no early param validation", self.code),
                    )
        return ()


class ProhibitedCompare(CodeCheck):
    code = "BS006"

    def check(self, n, s, c):
        if not isinstance(n, ast.Compare):
            return ()
        msg = []
        left = n.left
        for op, right in zip(n.ops, n.comparators):
            for side in (left, right):
                if isinstance(side, ast.Constant):
                    val = side.value
                    if val is None and isinstance(op, (ast.Eq, ast.NotEq)):
                        msg.append("use `is None` not `== None`")
                    if isinstance(val, bool) and isinstance(
                        op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)
                    ):
                        msg.append("avoid explicit bool compare")
            left = right
        if msg and not suppressed(s[n.lineno - 1], self.code):
            return ((n.lineno, "; ".join(set(msg)), self.code),)
        return ()


class NestingDepth(CodeCheck):
    code = "BS007"

    def _depth(self, n, l=0):
        kids = list(ast.iter_child_nodes(n))
        return max([l] + [self._depth(k, l + 1) for k in kids])

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            d = self._depth(n) - 1
            if d > c.max_nesting_depth and not suppressed(s[n.lineno - 1], self.code):
                return ((n.lineno, f"{n.name}: nesting depth {d}", self.code),)
        return ()


class WildcardImport(CodeCheck):
    code = "BS008"

    def check(self, n, s, c):
        if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
            if not suppressed(s[n.lineno - 1], self.code):
                return ((n.lineno, "wildcard import", self.code),)
        return ()


class ExecEval(CodeCheck):
    code = "BS009"

    def check(self, n, s, c):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in ("exec", "eval")
        ):
            if not suppressed(s[n.lineno - 1], self.code):
                return ((n.lino, f"{n.func.id}() call", self.code),)
        return ()


class DeadIf(CodeCheck):
    code = "BS010"

    def check(self, n, s, c):
        if (
            isinstance(n, ast.If)
            and isinstance(n.test, ast.Constant)
            and n.test.value in (False, 0, None)
        ):
            if not suppressed(s[n.lino - 1], self.code):
                return ((n.lino, "dead if-block", self.code),)
        return ()


class UnusedLocal(CodeCheck):
    code = "BS011"

    def check(self, n, s, c):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assigns, loads = defaultdict(list), set()
            params = {a.arg for a in n.args.args}
            for sub in ast.walk(n):
                if isinstance(sub, ast.Name):
                    if isinstance(sub.ctx, ast.Store) and sub.id not in params:
                        assigns[sub.id].append(sub.lino)
                    elif isinstance(sub.ctx, ast.Load):
                        loads.add(sub.id)
            return [
                (l[0], f"{n.name}: unused var '{v}'", self.code)
                for v, l in assigns.items()
                if v not in loads
                and not v.startswith("_")
                and not suppressed(s[l[0] - 1], self.code)
            ]
        return ()


class MaxArgs(CodeCheck):
    code = "BS012"

    def check(self, n, s, c):
        if isinstance(n, ast.FunctionDef) and len(n.args.args) > 5:
            if not suppressed(s[n.lino - 1], self.code):
                return (
                    (
                        n.lino,
                        f"{n.name}: too many args ({len(n.args.args)} > 5)",
                        self.code,
                    ),
                )
        return ()


class BareExcept(CodeCheck):
    code = "BS013"

    def check(self, n, s, c):
        if isinstance(n, ast.Try):
            for h in n.handlers:
                if h.type is None and not suppressed(s[n.lino - 1], self.code):
                    return ((n.lino, "Bare except used", self.code),)
        return ()


class ForbiddenCalls(CodeCheck):
    code = "BS014"

    def check(self, n, s, c):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in {"print", "eval", "exec"}
        ):
            if not suppressed(s[n.lino - 1], self.code):
                return ((n.lino, f"Forbidden call {n.func.id}()", self.code),)
        return ()


class GlobalNonlocal(CodeCheck):
    code = "BS015"

    def check(self, n, s, c):
        if isinstance(n, (ast.Global, ast.Nonlocal)) and not suppressed(
            s[n.lino - 1], self.code
        ):
            return (
                (
                    n.lino,
                    f"{'Global' if isinstance(n, ast.Global) else 'Nonlocal'} discouraged",
                    self.code,
                ),
            )
        return ()


class LongLines(CodeCheck):
    code = "BS016"

    def check(self, n, s, c):
        if isinstance(n, ast.Module):
            return [
                (i + 1, "Line exceeds 88 chars", self.code)
                for i, l in enumerate(s)
                if len(l) > 88 and not suppressed(l, self.code)
            ]
        return ()


class MixedTabsSpaces(CodeCheck):
    code = "BS017"

    def check(self, n, s, c):
        if isinstance(n, ast.Module):
            return [
                (i + 1, "Mixed tabs/spaces", self.code)
                for i, l in enumerate(s)
                if "\t" in l and " " in l and not suppressed(l, self.code)
            ]
        return ()


# built-in registry
BUILTIN_CHECKS: Dict[str, CodeCheck] = {
    "function_length": FunctionLength(),
    "assertion_density": AssertionDensity(),
    "mutable_default": MutableDefault(),
    "mixed_return": MixedReturn(),
    "parameter_validation": ParamValidation(),
    "prohibited_compare": ProhibitedCompare(),
    "nesting_depth": NestingDepth(),
    "wildcard_import": WildcardImport(),
    "exec_eval": ExecEval(),
    "dead_if": DeadIf(),
    "unused_local": UnusedLocal(),
    "max_args": MaxArgs(),
    "bare_except": BareExcept(),
    "forbidden_calls": ForbiddenCalls(),
    "global_nonlocal": GlobalNonlocal(),
    "long_lines": LongLines(),
    "mixed_tabs_spaces": MixedTabsSpaces(),
}


# ── load external checks/ directory if present ───────────────────────────────
def load_external_checks() -> Dict[str, CodeCheck]:
    path = Path("checks")
    if not path.is_dir():
        return {}
    checks = {}
    sys.path.insert(0, str(path.parent))
    for py in path.glob("*.py"):
        mod = importlib.import_module(f"checks.{py.stem}")
        for name, obj in inspect.getmembers(mod, lambda x: isinstance(x, CodeCheck)):
            checks[name] = obj
    return checks


CHECKS: Dict[str, CodeCheck] = {**BUILTIN_CHECKS, **load_external_checks()}


# ── Analyzer (per file) ──────────────────────────────────────────────────────
class Analyzer(ast.NodeVisitor):
    def __init__(self, path: Path, src: str, cfg: Config):
        self.path, self.src, self.cfg = path, src.splitlines(), cfg
        self.viol: List[Tuple[int, str, str]] = []
        self.funcs = self.asserts = 0

    def visit(self, node: ast.AST):
        active = (
            CHECKS
            if "all" in self.cfg.checks
            else {k: CHECKS[k] for k in self.cfg.checks if k in CHECKS}
        )
        for chk in active.values():
            self.viol.extend(chk.check(node, self.src, self.cfg))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.funcs += 1
        if isinstance(node, ast.Assert):
            self.asserts += 1
        super().visit(node)

    def run(self):
        self.visit(ast.parse("\n".join(self.src), filename=str(self.path)))
        avg = self.asserts / self.funcs if self.funcs else 0
        return dict(
            file=str(self.path),
            violations=sorted(self.viol, key=lambda t: t[0]),
            metrics=dict(
                funcs=self.funcs, asserts=self.asserts, avg=avg, lines=len(self.src)
            ),
        )


# ── runtime fuzz (same as v1.1 but UUID safe) ────────────────────────────────
def runtime_fuzz(path: Path) -> List[Tuple[int, str, str]]:
    modname = f"target_{path.stem}_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(modname, path)
    if not spec or not spec.loader:
        return []
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    out = []
    for name, fn in inspect.getmembers(module, inspect.isfunction):
        # Skip pytest fixtures
        if hasattr(fn, "_pytestfixturefunction"):
            continue
        lino = fn.__code__.co_firstlineno
        try:
            res = fn(**{p: None for p in inspect.signature(fn).parameters})
            ann = fn.__annotations__.get("return")
            if res is None and ann and ann is not type(None):  # noqa
                out.append((lino, f"{name}: unexpected None return", "RTN001"))
        except Exception as e:
            out.append((lino, f"{name}: crash on None args ({e})", "RTN002"))
        if not fn.__doc__ or not fn.__doc__.strip():
            out.append((lino, f"{name}: missing docstring", "RTN003"))
    return out


# ── external linters (batch) ─────────────────────────────────────────────────
def _run(cmd: List[str], label: str) -> List[str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        LOG.warning(f"{label} not found")
        return []
    return res.stdout.splitlines() + res.stderr.splitlines()


def external_lint(paths: List[Path], cfg: Config) -> List[Tuple[int, str, str]]:
    viol = []
    # Flake8 or Ruff
    cmd = ["ruff", "check"] if cfg.use_ruff else ["flake8"]
    cmd += [str(p) for p in paths]
    if cfg.max_complexity:
        cmd.append(f"--max-complexity={cfg.max_complexity}")
    flk = _run(cmd, "ruff" if cfg.use_ruff else "flake8")
    for l in flk:
        p = l.split(":", 3)
        if len(p) >= 4:
            viol.append(
                (
                    int(p[1]),
                    f"{'ruff' if cfg.use_ruff else 'flake8'}: {p[3].strip()}",
                    "EXT001",
                )
            )

    # Black and Isort
    if cfg.format_check:
        for p in paths:
            viol.extend(
                [
                    (1, f"black: formatting issues in {p}", "EXT004")
                    for _ in _run(["black", "--check", str(p)], "black")
                    if _
                ]
            )
            viol.extend(
                [
                    (1, f"isort: formatting issues in {p}", "EXT005")
                    for _ in _run(["isort", "--check-only", str(p)], "isort")
                    if _
                ]
            )

    # Mypy
    if cfg.run_mypy:
        my = _run(["mypy", "--ignore-missing-imports", *map(str, paths)], "mypy")
        for l in my:
            if ": error:" in l:
                p = l.split(":", 3)
                if len(p) >= 4:
                    viol.append((int(p[1]), f"mypy: {p[3].strip()}", "EXT002"))

    # Bandit
    if cfg.run_bandit:
        roots = {p.parent for p in paths}
        bn = _run(["bandit", "-q", "-r", *{str(r) for r in roots}], "bandit")
        for l in bn:
            if "Issue:" in l:
                parts = l.split(":")
                if len(parts) >= 4:
                    try:
                        lineno = int(parts[1].strip())
                        viol.append(
                            (lineno, f"bandit: {':'.join(parts[3:]).strip()}", "EXT003")
                        )
                    except ValueError:
                        continue

    # pip-audit
    if cfg.run_audit and Path("requirements.txt").exists():
        pa = _run(["pip-audit", "-r", "requirements.txt"], "pip-audit")
        for l in pa:
            if "Vulnerability" in l:
                viol.append((1, f"pip-audit: {l.strip()}", "EXT006"))

    return viol


# ── util ─────────────────────────────────────────────────────────────────────
def collect(patterns: List[str]) -> List[Path]:
    res = []
    for pat in patterns:
        p = Path(pat)
        if p.is_file() and p.suffix == ".py":
            res.append(p.resolve())
        elif p.is_dir():
            res.extend(p.resolve().rglob("*.py"))
    return sorted(set(res))


def analyze_file(
    f: Path, cfg: Config, ext: List[Tuple[int, str, str]]
) -> Dict[str, Any]:
    """Analyze a single file for code quality violations."""
    ana = Analyzer(f, f.read_text(encoding="utf-8"), cfg).run()
    ana["violations"].extend(runtime_fuzz(f))
    ana["violations"].extend([v for v in ext if str(f) in v[1]])
    return ana


def _analyze_file_wrapper(args):
    """Wrapper function for multiprocessing to avoid pickling issues with lambda."""
    file, cfg, ext = args
    return analyze_file(file, cfg, ext)


def run_quality(cfg: Config) -> List[Dict[str, Any]]:
    files = collect(cfg.files)
    ext = external_lint(files, cfg)

    with ProcessPoolExecutor() as pool:
        # Create a list of tuples with necessary arguments
        args = [(f, cfg, ext) for f in files]
        # Use the wrapper function instead of a lambda
        results = list(pool.map(_analyze_file_wrapper, args))
    return results


def report(res: List[Dict[str, Any]], fmt: str, output_file: str = None):
    if fmt == "json":
        output = json.dumps(res, indent=2)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)
        return

    # Markdown output for parse_bs_tasks.py
    if fmt == "markdown":
        output = []
        for r in res:
            filename = r["file"]
            output.append(f"### {filename}")
            for ln, msg, code in r["violations"]:
                output.append(f"- Line {ln}: {msg} (code: {code})")
            output.append("")  # Blank line for readability
        output_str = "\n".join(output)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_str)
        else:
            print(output_str)
        return

    # Default text output
    for r in res:
        LOG.info(f"\n{r['file']}")
        for ln, msg, code in r["violations"]:
            LOG.info(f" {ln:4d}: {msg} (code: {code})")
        m = r["metrics"]
        LOG.info(
            f" metrics: {m['funcs']} funcs, {m['avg']:.2f} avg asserts, {m['lines']} lines"
        )


# ── CLI ──────────────────────────────────────────────────────────────────────
def cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("code-quality gate")
    p.add_argument(
        "--files",
        nargs="*",
        default=["."],
        help="Files or directories to analyze (e.g., src/ parse_bs_tasks.py)",
    )
    p.add_argument("--config", type=Path, help="Path to YAML config file")
    p.add_argument(
        "--strict", action="store_true", help="Enable strict mode for checks"
    )
    p.add_argument(
        "--max-func-lines",
        type=int,
        default=50,
        help="Maximum allowed lines per function",
    )
    p.add_argument(
        "--max-nesting-depth", type=int, default=3, help="Maximum nesting depth"
    )
    p.add_argument("--run-mypy", action="store_true", help="Run Mypy type checker")
    p.add_argument(
        "--run-bandit", action="store_true", help="Run Bandit security linter"
    )
    p.add_argument(
        "--max-complexity", type=int, default=10, help="Maximum cyclomatic complexity"
    )
    p.add_argument("--use-ruff", action="store_true", help="Use Ruff instead of Flake8")
    p.add_argument(
        "--format-check", action="store_true", help="Run Black and Isort checks"
    )
    p.add_argument(
        "--run-audit", action="store_true", help="Run pip-audit for dependencies"
    )
    p.add_argument("--checks", help="Comma-separated list of checks to run")
    p.add_argument(
        "--output",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )
    p.add_argument("--output-file", type=str, default=None, help="File to write output")
    return p


def main():
    parser = cli_parser()
    args = parser.parse_args()
    if not args.files:
        parser.error("At least one file or directory must be specified with --files")
    cfg = Config()
    if args.config:
        cfg.load_yaml(args.config)
    cfg.load_ns(args)
    res = run_quality(cfg)
    report(res, cfg.output, args.output_file)
    if any(r["violations"] for r in res):
        sys.exit(1)


# ── pytest integration ───────────────────────────────────────────────────────
def pytest_addoption(parser: pytest.Parser):
    g = parser.getgroup("code-quality")
    g.addoption(
        "--code-quality", action="store_true", help="Enable code quality checks"
    )
    g.addoption(
        "--files",
        action="append",
        default=[],
        help="Files or directories to analyze (e.g., src/ parse_bs_tasks.py)",
    )
    g.addoption("--strict", action="store_true", help="Enable strict mode for checks")
    g.addoption(
        "--max-func-lines",
        type=int,
        default=50,
        help="Maximum allowed lines per function",
    )
    g.addoption(
        "--max-nesting-depth", type=int, default=3, help="Maximum nesting depth"
    )
    g.addoption("--run-mypy", action="store_true", help="Run Mypy type checker")
    g.addoption("--run-bandit", action="store_true", help="Run Bandit security linter")
    g.addoption(
        "--max-complexity", type=int, default=10, help="Maximum cyclomatic complexity"
    )
    g.addoption("--use-ruff", action="store_true", help="Use Ruff instead of Flake8")
    g.addoption(
        "--format-check", action="store_true", help="Run Black and Isort checks"
    )
    g.addoption(
        "--run-audit", action="store_true", help="Run pip-audit for dependencies"
    )
    g.addoption("--checks", help="Comma-separated list of checks to run")
    g.addoption(
        "--output",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format",
    )
    g.addoption("--output-file", type=str, default=None, help="File to write output")


def pytest_generate_tests(metafunc: pytest.Metafunc):
    if not metafunc.config.getoption("--code-quality"):
        return
    cfg = Config.from_pytest(metafunc.config)
    files = collect(cfg.files)
    active = (
        CHECKS
        if "all" in cfg.checks
        else {k: CHECKS[k] for k in cfg.checks if k in CHECKS}
    )
    metafunc.parametrize("bs_file", files, ids=lambda p: str(p))
    metafunc.parametrize("bs_check", list(active.keys()), ids=str)


@pytest.fixture(scope="session")
def bs_config(pytestconfig) -> Config:
    return Config.from_pytest(pytestconfig)


def test_bs(bs_file: Path, bs_check: str, bs_config: Config):
    """one test per file×check for granular failure reporting"""
    src = bs_file.read_text(encoding="utf-8")
    ana = Analyzer(bs_file, src, bs_config)
    ana.visit(ast.parse(src, filename=str(bs_file)))
    offenses = [v for v in ana.viol if v[2] == CHECKS[bs_check].code]
    offenses.extend(
        [
            v
            for v in runtime_fuzz(bs_file)
            if v[2].startswith("RTN") and bs_check == "runtime"
        ]
    )
    assert not offenses, "\n".join(f"{ln}: {msg}" for ln, msg, _ in offenses)


# run standalone
if __name__ == "__main__":
    main()
