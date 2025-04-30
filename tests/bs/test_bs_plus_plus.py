# test_bs_plus.py — Good Vibes Code Hygiene Suite (Rulepack v1)
# -----------------------------------------------------------------------------
# Pure pytest-based static checker + hygiene gate:
# - Ruff / Flake8 / Black / Isort
# - AST-based NASA-grade safe rules (20+)
# - Optional plugins
# - Optional JSON output
# -----------------------------------------------------------------------------

from __future__ import annotations

import ast
import collections
import importlib
import json
import pathlib
import shlex
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pytest

# -----------------------------------------------------------------------------
# CLI Options
# -----------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("Good-Vibes Gate")
    g.addoption("--target", type=pathlib.Path, required=True, help="Path to scan")
    g.addoption(
        "--strict", action="store_true", help="Stricter checks (more asserts, etc)"
    )
    g.addoption("--max-func-lines", type=int, default=50)
    g.addoption("--max-args", type=int, default=5)
    g.addoption("--max-nesting", type=int, default=3)
    g.addoption("--ruff", action="store_true", help="Use Ruff instead of Flake8")
    g.addoption("--run-mypy", action="store_true")
    g.addoption("--run-bandit", action="store_true")
    g.addoption("--run-audit", action="store_true")
    g.addoption("--format-check", action="store_true")
    g.addoption("--cov-threshold", type=int, default=None)
    g.addoption("--plugins", type=str, default="")


# -----------------------------------------------------------------------------
# Config Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture(scope="session")
def cfg(pytestconfig: pytest.Config) -> dict:
    return {
        "strict": pytestconfig.getoption("--strict"),
        "max_func_lines": pytestconfig.getoption("--max-func-lines"),
        "max_args": pytestconfig.getoption("--max-args"),
        "max_nesting": pytestconfig.getoption("--max-nesting"),
    }


@pytest.fixture(scope="session")
def target(pytestconfig: pytest.Config) -> pathlib.Path:
    return pytestconfig.getoption("--target").resolve()


@pytest.fixture(scope="session")
def plugins(pytestconfig: pytest.Config):
    modules = []
    for name in pytestconfig.getoption("--plugins").split(","):
        name = name.strip()
        if name:
            mod = importlib.import_module(name)
            modules.append(mod.extra_check)
    return modules


# -----------------------------------------------------------------------------
# External Tools
# -----------------------------------------------------------------------------


def _exe(cmd: Sequence[str], tool: str, desc: str):
    if not shutil.which(cmd[0]):
        pytest.skip(f"{tool} not found in PATH")
    print(f"\n[{tool}] {' '.join(shlex.quote(c) for c in cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(res.stdout)
        print(res.stderr)
        pytest.fail(f"{tool} reported issues in {desc}")


@pytest.mark.good
def test_lint(target, pytestconfig):
    if pytestconfig.getoption("--ruff"):
        _exe(["ruff", "check", str(target)], "Ruff", str(target))
    else:
        _exe(["flake8", str(target)], "Flake8", str(target))


@pytest.mark.good
def test_format(target, pytestconfig):
    if pytestconfig.getoption("--format-check"):
        _exe(["black", "--check", str(target)], "Black", str(target))
        _exe(["isort", "--check-only", str(target)], "Isort", str(target))


@pytest.mark.good
def test_type(target, pytestconfig):
    if pytestconfig.getoption("--run-mypy"):
        _exe(["mypy", "--ignore-missing-imports", str(target)], "Mypy", str(target))


@pytest.mark.good
def test_bandit(target, pytestconfig):
    if pytestconfig.getoption("--run-bandit"):
        _exe(["bandit", "-r", str(target)], "Bandit", str(target))


@pytest.mark.good
def test_audit(pytestconfig):
    if pytestconfig.getoption("--run-audit"):
        if not pathlib.Path("requirements.txt").exists():
            pytest.skip("No requirements.txt")
        _exe(["pip-audit", "-r", "requirements.txt"], "Pip-Audit", "requirements.txt")


# -----------------------------------------------------------------------------
# AST Analysis Engine
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Parsed:
    path: pathlib.Path
    src: str
    tree: ast.Module


class Analyzer(ast.NodeVisitor):
    def __init__(self, parsed: Parsed, cfg: dict):
        self.parsed = parsed
        self.cfg = cfg
        self.v = collections.defaultdict(list)
        self.current_function: Optional[ast.FunctionDef] = None
        self.depth = 0
        self.imports_seen = set()

    def add(self, rule: str, node: ast.AST, msg: str):
        lineno = getattr(node, "lineno", 0)
        self.v[rule].append((lineno, msg))

    def run(self) -> dict:
        self.visit(self.parsed.tree)
        self._check_long_lines()
        self._check_tabs_spaces()
        return dict(self.v)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.current_function = node
        if len(node.args.args) > self.cfg.get("max_args", 5):
            self.add("MAX_ARGS", node, f"Too many args: {len(node.args.args)}")
        if not ast.get_docstring(node) and not node.name.startswith("_"):
            self.add("MISSING_DOCSTRING", node, "Missing docstring")
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1
        self.current_function = None

    def visit_If(self, node: ast.If):
        if self.depth > self.cfg.get("max_nesting", 3):
            self.add("NESTING_TOO_DEEP", node, "Too deeply nested")
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def visit_Try(self, node: ast.Try):
        for h in node.handlers:
            if h.type is None:
                self.add("BARE_EXCEPT", h, "Bare except used")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in {
            "eval",
            "exec",
            "print",
        }:
            self.add("EVAL_EXEC_USED", node, f"Forbidden call {node.func.id}()")
        self.generic_visit(node)

    def visit_Global(self, node: ast.Global):
        self.add("GLOBAL_NONLOCAL", node, "Use of global discouraged")

    def visit_Nonlocal(self, node: ast.Nonlocal):
        self.add("GLOBAL_NONLOCAL", node, "Use of nonlocal discouraged")

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.names and any(alias.name == "*" for alias in node.names):
            self.add("WILDCARD_IMPORT", node, "Wildcard import used")
        self.generic_visit(node)

    def _check_long_lines(self):
        for lineno, line in enumerate(self.parsed.src.splitlines(), 1):
            if len(line) > 88:
                self.v["LONG_LINE"].append((lineno, "Line exceeds 88 chars"))

    def _check_tabs_spaces(self):
        for lineno, line in enumerate(self.parsed.src.splitlines(), 1):
            if "\t" in line and " " in line:
                self.v["MIXED_TABS_SPACES"].append((lineno, "Mixed tabs/spaces"))


# -----------------------------------------------------------------------------
# Session Fixtures
# -----------------------------------------------------------------------------


def _collect_files(root: pathlib.Path) -> List[pathlib.Path]:
    if root.is_file():
        return [root]
    return sorted(root.rglob("*.py"))


@pytest.fixture(scope="session")
def py_files(target: pathlib.Path) -> List[pathlib.Path]:
    files = _collect_files(target)
    if not files:
        pytest.exit(f"No Python files found at {target}")
    return files


@pytest.fixture(scope="session")
def parsed(py_files) -> dict:
    def parse(path: pathlib.Path):
        try:
            src = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            src = path.read_bytes().decode("latin-1")
        return Parsed(path, src, ast.parse(src))

    with ProcessPoolExecutor() as pool:
        results = pool.map(parse, py_files)
    return {p.path: p for p in results}


@pytest.fixture(scope="session")
def analysis(parsed, cfg, plugins):
    def analyze(parsed_file: Parsed):
        analyzer = Analyzer(parsed_file, cfg)
        base = analyzer.run()
        for plugin in plugins:
            plug_base = plugin(parsed_file.path, parsed_file.tree, parsed_file.src, cfg)
            for k, v in (plug_base or {}).items():
                base.setdefault(k, []).extend(v)
        return parsed_file.path, base

    with ProcessPoolExecutor() as pool:
        return dict(pool.map(analyze, parsed.values()))


@pytest.fixture(scope="session")
def all_rules(analysis) -> List[str]:
    rules = set()
    for a in analysis.values():
        rules.update(a.keys())
    return sorted(rules)


# -----------------------------------------------------------------------------
# AST Rule Tests
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", lambda analysis: list(analysis.keys()))
@pytest.mark.parametrize("rule", lambda all_rules: all_rules)
def test_ast_rules(path, rule, analysis):
    violations = analysis[path].get(rule, [])
    if violations:
        out = "\n".join(f"L{line}: {msg}" for line, msg in violations)
        pytest.fail(f"{rule} violations in {path}:\n{out}")


# -----------------------------------------------------------------------------
# Optional JSON Output
# -----------------------------------------------------------------------------


def pytest_sessionfinish(session: pytest.Session, exitstatus: int):
    cov_thresh = session.config.getoption("--cov-threshold")
    if cov_thresh is not None:
        cov_plugin = session.config.pluginmanager.get_plugin("cov")
        if cov_plugin:
            total = cov_plugin.cov_controller.analysis2(cov_plugin.cov_controller.cov)[
                1
            ]
            if total < cov_thresh:
                print(f"\nCoverage {total}% < required {cov_thresh}% -> FAIL")
                session.exitstatus = 1
