# test_bs_plus.py – Code‑Quality Gate ("Good Vibes" Edition)
# ---------------------------------------------------------------------------
# Features
#   • Fast lint: Ruff (falls back to Flake8) + optional Black / Isort format‑gate
#   • Type, security, vulnerability & coverage thresholds (mypy, bandit, pip‑audit)
#   • AST pass with extensible plug‑in architecture (+built‑in rule pack)
#   • Parallel analysis across files – quick feedback on large repos
#   • Pure‑pytest: integrate smoothly in CI, easy CLI flags
# ---------------------------------------------------------------------------
# Usage examples
#   pytest -q test_bs_plus.py --target src/ --strict --run-mypy --run-bandit --ruff \
#         --format-check --max-complexity 10 --cov-threshold 80
#   pytest -q test_bs_plus.py --target my_module.py --plugins=my_checks.extra_rules
# ---------------------------------------------------------------------------
from __future__ import annotations

import ast
import collections
import importlib
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import pytest

# ---------------------------------------------------------------------------
# PyPI tool probes (skip tests gracefully if missing) – done once at import time
# ---------------------------------------------------------------------------
for _pkg in ("ruff", "flake8", "mypy", "bandit", "pip_audit"):
    try:
        pytest.importorskip(_pkg)
    except ImportError:
        pass

# ---------------------------------------------------------------------------
# CLI options
# ---------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("Good‑Vibes Gate")
    g.addoption(
        "--target",
        type=pathlib.Path,
        help="Path to a .py file or package dir to analyse",
        required=True,
    )
    g.addoption(
        "--strict",
        action="store_true",
        help="Tighten thresholds (asserts, param validation)",
    )
    g.addoption("--max-func-lines", type=int, default=50, help="Max lines per function")
    g.addoption(
        "--max-complexity",
        type=int,
        default=None,
        help="Cyclomatic complexity max (MCCabe / Ruff)",
    )
    g.addoption("--ruff", action="store_true", help="Run Ruff instead of Flake8")
    g.addoption(
        "--format-check", action="store_true", help="Run Black + Isort in --check mode"
    )
    g.addoption("--run-mypy", action="store_true", help="Run mypy type checker")
    g.addoption("--run-bandit", action="store_true", help="Run Bandit security scanner")
    g.addoption(
        "--run-audit", action="store_true", help="Run pip‑audit for dependency vulns"
    )
    g.addoption(
        "--cov-threshold",
        type=int,
        default=None,
        help="Fail if coverage < threshold (requires pytest‑cov)",
    )
    g.addoption(
        "--plugins",
        type=str,
        default="",
        help="Comma‑separated list of module paths exposing extra_check(file, tree, src, cfg)",
    )


# ---------------------------------------------------------------------------
# pytest configuration validation
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    target: pathlib.Path = config.getoption("--target")
    if not target.exists():
        pytest.exit(f"--target path not found: {target}")
    if config.getoption("--cov-threshold") and not config.pluginmanager.hasplugin(
        "pytest_cov"
    ):
        pytest.exit("--cov-threshold needs pytest‑cov plugin installed")


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _exe(cmd: Sequence[str], *, tool: str, desc: str) -> None:
    """Run external tool, surface output on failure."""
    if not shutil.which(cmd[0]):
        pytest.skip(f"{tool} executable not in PATH – skipping {tool} check")
    print(f"\n[{tool}] ", " ".join(shlex.quote(c) for c in cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.stdout:
        print(res.stdout)
    if res.stderr:
        print(res.stderr, file=sys.stderr)
    if res.returncode != 0:
        pytest.fail(f"{tool} reported issues for {desc} (exit {res.returncode})")


# ---------------------------------------------------------------------------
# Fixtures – global config knobs
# ---------------------------------------------------------------------------

pytest_plugins: list[str] = []  # silence IDEs


@pytest.fixture(scope="session")
def cfg(pytestconfig: pytest.Config) -> Dict[str, Any]:
    return {
        "strict": pytestconfig.getoption("--strict"),
        "max_func_lines": pytestconfig.getoption("--max-func-lines"),
    }


@pytest.fixture(scope="session")
def target(pytestconfig: pytest.Config) -> pathlib.Path:
    return pytestconfig.getoption("--target").resolve()


# ---------------------------------------------------------------------------
# Collect python files
# ---------------------------------------------------------------------------


def _collect_py_files(root: pathlib.Path) -> List[pathlib.Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    return sorted(root.rglob("*.py"))


@pytest.fixture(scope="session")
def py_files(target: pathlib.Path) -> List[pathlib.Path]:
    files = _collect_py_files(target)
    if not files:
        pytest.fail(f"No .py files found under {target}")
    return files


# ---------------------------------------------------------------------------
# Parse each file once (parallelised)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Parsed:
    path: pathlib.Path
    src: str
    tree: ast.Module


def _parse_file(path: pathlib.Path) -> Parsed:
    try:
        src = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        src = path.read_bytes().decode("latin-1")
    tree = ast.parse(src, filename=str(path))
    return Parsed(path, src, tree)


@pytest.fixture(scope="session")
def parsed(py_files: List[pathlib.Path]) -> Dict[pathlib.Path, Parsed]:
    with ProcessPoolExecutor() as pool:
        results = pool.map(_parse_file, py_files)
    return {p.path: p for p in results}


# ---------------------------------------------------------------------------
# External tool checks (lint / type / security / format / deps)
# ---------------------------------------------------------------------------


@pytest.mark.good
def test_lint(target: pathlib.Path, pytestconfig: pytest.Config):
    """Ruff or Flake8."""
    if pytestconfig.getoption("--ruff"):
        cmd = ["ruff", "check", str(target)]
        max_complexity = pytestconfig.getoption("--max-complexity")
        if max_complexity:
            cmd += ["--select", "C90", f"--flake8-max-complexity={max_complexity}"]
        _exe(cmd, tool="Ruff", desc=str(target))
    else:
        cmd = [sys.executable, "-m", "flake8", str(target)]
        if pytestconfig.getoption("--max-complexity"):
            cmd.append(f"--max-complexity={pytestconfig.getoption('--max-complexity')}")
        _exe(cmd, tool="Flake8", desc=str(target))


@pytest.mark.good
def test_format(target: pathlib.Path, pytestconfig: pytest.Config):
    if not pytestconfig.getoption("--format-check"):
        pytest.skip("Format gate disabled")
    _exe(["black", "--check", str(target)], tool="Black", desc=str(target))
    _exe(["isort", "--check-only", str(target)], tool="Isort", desc=str(target))


@pytest.mark.good
def test_type(target: pathlib.Path, pytestconfig: pytest.Config):
    if not pytestconfig.getoption("--run-mypy"):
        pytest.skip("mypy disabled")
    _exe(
        [sys.executable, "-m", "mypy", "--ignore-missing-imports", str(target)],
        tool="mypy",
        desc=str(target),
    )


@pytest.mark.good
def test_bandit(target: pathlib.Path, pytestconfig: pytest.Config):
    if not pytestconfig.getoption("--run-bandit"):
        pytest.skip("bandit disabled")
    _exe(
        [sys.executable, "-m", "bandit", "-r", str(target)],
        tool="Bandit",
        desc=str(target),
    )


@pytest.mark.good
def test_audit(pytestconfig: pytest.Config):
    if not pytestconfig.getoption("--run-audit"):
        pytest.skip("pip‑audit disabled")
    req = pathlib.Path("requirements.txt")
    if not req.exists():
        pytest.skip("requirements.txt not found – skipping audit")
    _exe(
        [sys.executable, "-m", "pip_audit", "-r", "requirements.txt"],
        tool="pip‑audit",
        desc="requirements.txt",
    )


# ---------------------------------------------------------------------------
# Built‑in AST rule pack
# ---------------------------------------------------------------------------

Rule = Tuple[int, str]  # (line, message)


class Analyzer(ast.NodeVisitor):
    """Walks the AST and records violations."""

    RULE_FUNC_LEN = "FUNC_LEN"
    RULE_ASSERT_DENS = "ASSERT_DENS"
    RULE_MUTABLE_DEFAULT = "MUT_DEF"

    def __init__(self, parsed: Parsed, cfg: Dict[str, Any]):
        self.parsed = parsed
        self.cfg = cfg
        self.v: Dict[str, List[Rule]] = collections.defaultdict(list)
        self._func_data: Optional[dict[str, Any]] = None

    # helpers -------------------------------------------------------------

    def add(self, rule: str, node: ast.AST, msg: str) -> None:
        self.v[rule].append((getattr(node, "lineno", 0), msg))

    def count_lines(self, node: ast.AST) -> int:
        if hasattr(node, "end_lineno"):
            return node.end_lineno - node.lineno + 1  # type: ignore[attr-defined]
        return (
            max((getattr(n, "lineno", 0) for n in ast.walk(node)), default=node.lineno)
            - node.lineno
            + 1
        )

    # Visitor overrides ---------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef):
        max_lines = self.cfg["max_func_lines"]
        if self.count_lines(node) > max_lines:
            self.add(
                self.RULE_FUNC_LEN,
                node,
                f"Function '{node.name}' exceeds {max_lines} lines",
            )

        # setup func state
        self._func_data = {"asserts": 0, "params": {a.arg for a in node.args.args}}
        self.generic_visit(node)
        # after visiting children
        if self._func_data and self._func_data["asserts"] < (
            2 if self.cfg["strict"] else 1
        ):
            self.add(
                self.RULE_ASSERT_DENS, node, f"Function '{node.name}' too few asserts"
            )
        self._func_data = None

    def visit_Assert(self, node: ast.Assert):
        if self._func_data is not None:
            self._func_data["asserts"] += 1
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg):
        # skip arg nodes
        pass

    def visit_Name(self, node: ast.Name):
        # track later?
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword):
        if isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
            self.add(
                self.RULE_MUTABLE_DEFAULT, node, "Mutable default value in keyword arg"
            )
        self.generic_visit(node)

    # run -----------------------------------------------------------------

    def run(self) -> Dict[str, List[Rule]]:
        self.visit(self.parsed.tree)  # uses pre‑parsed tree
        return dict(self.v)


# ---------------------------------------------------------------------------
# Plug‑in loader utility
# ---------------------------------------------------------------------------


def _load_plugins(
    spec: str,
) -> List[
    Callable[[pathlib.Path, ast.AST, str, Dict[str, Any]], Dict[str, List[Rule]]]
]:
    if not spec:
        return []
    loaded = []
    for mod_path in spec.split(","):
        try:
            mod = importlib.import_module(mod_path.strip())
            fn = getattr(mod, "extra_check", None)
            if not callable(fn):  # pragma: no cover
                pytest.exit(f"Plugin {mod_path} lacks 'extra_check' callable")
            loaded.append(fn)  # type: ignore[arg-type]
        except Exception as e:  # pragma: no cover
            pytest.exit(f"Failed to import plugin {mod_path}: {e}")
    return loaded


@pytest.fixture(scope="session")
def plugins(pytestconfig: pytest.Config):
    return _load_plugins(pytestconfig.getoption("--plugins"))


# ---------------------------------------------------------------------------
# Run analysis across files in parallel once per session
# ---------------------------------------------------------------------------

Analysis = Dict[pathlib.Path, Dict[str, List[Rule]]]


def _analyze(
    parsed: Parsed,
    cfg: Dict[str, Any],
    plugin_fns: Sequence[
        Callable[[pathlib.Path, ast.AST, str, Dict[str, Any]], Dict[str, List[Rule]]]
    ],
) -> Tuple[pathlib.Path, Dict[str, List[Rule]]]:
    an = Analyzer(parsed, cfg)
    v = an.run()
    # plug‑ins
    for fn in plugin_fns:
        try:
            plug_v = fn(parsed.path, parsed.tree, parsed.src, cfg) or {}
            for k, lst in plug_v.items():
                v.setdefault(k, []).extend(lst)
        except Exception as e:
            pytest.fail(f"Plugin {fn.__module__} crashed on {parsed.path}: {e}")
    return parsed.path, v


@pytest.fixture(scope="session")
def analysis(parsed: Dict[pathlib.Path, Parsed], cfg: Dict[str, Any], plugins):
    with ProcessPoolExecutor() as pool:
        res = pool.map(lambda p: _analyze(p[1], cfg, plugins), parsed.items())
    return dict(res)


# ---------------------------------------------------------------------------
# Parametrised AST tests – each rule, each file
# ---------------------------------------------------------------------------


def _format(v: List[Rule]) -> str:
    return "\n".join(f"  L{ln}: {msg}" for ln, msg in sorted(v))


# all built‑in + plugin rule ids
@pytest.fixture(scope="session")
def all_rules(analysis: Analysis) -> List[str]:
    rules = set()
    for v in analysis.values():
        rules.update(v.keys())
    return sorted(rules)


@pytest.mark.parametrize("path", lazy := lambda analysis: list(analysis.keys()))
@pytest.mark.parametrize("rule", lambda all_rules: all_rules)
def test_ast_rules(path, rule, analysis: Analysis):  # type: ignore[valid-type]
    violations = analysis[path].get(rule, [])
    assert not violations, f"{rule} violations in {path}:\n{_format(violations)}"


# ---------------------------------------------------------------------------
# Coverage gate (run after user test session)
# ---------------------------------------------------------------------------


def pytest_sessionfinish(session: pytest.Session, exitstatus: int):
    cov_threshold = session.config.getoption("--cov-threshold")
    if cov_threshold is None:
        return
    cov_plugin = session.config.pluginmanager.get_plugin("cov")
    if not cov_plugin:
        return
    total = cov_plugin.cov_controller.analysis2(cov_plugin.cov_controller.cov)[1]
    if total < cov_threshold:
        session.exitstatus = 1
        print(f"\n\nCoverage {total:.1f}% < threshold {cov_threshold}% -> FAIL")
