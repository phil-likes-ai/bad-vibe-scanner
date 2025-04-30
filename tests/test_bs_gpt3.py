# test_bs.py
import ast
import subprocess
from pathlib import Path


import pytest

# --------------------------------------------------------------------------- #
#  Pytest command-line switches                                               #
# --------------------------------------------------------------------------- #
def pytest_addoption(parser):
    parser.addoption(
        "--script",
        action="store",
        default=None,
        help="Target Python file or directory to test",
    )
    parser.addoption(
        "--strict",
        action="store_true",
        default=False,
        help="Enable strict NASA-style checks",
    )
    parser.addoption(
        "--max-func-lines",
        action="store",
        type=int,
        default=50,
        help="Maximum allowed lines in a function (default 50)",
    )
    parser.addoption(
        "--run-mypy",
        action="store_true",
        default=False,
        help="Run mypy static type-checking",
    )
    parser.addoption(
        "--run-bandit",
        action="store_true",
        default=False,
        help="Run Bandit security scan",
    )
    parser.addoption(
        "--max-complexity",
        action="store",
        type=int,
        default=None,
        help="Cyclomatic-complexity threshold for flake8-mccabe",
    )


# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#  Helpers                                                                    #
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def target_files(request):
    """Return a sorted list of *.py files under --script (file or package)."""
    root = request.config.getoption("--script")
    if not root:
        pytest.skip("Use --script=path/to/code to specify target")
    root = Path(root)
    if not root.exists():
        pytest.fail(f"--script path does not exist: {root}")

    if root.is_file():
        files = [root] if root.suffix == ".py" else []
    else:  # directory / package
        files = [p for p in root.rglob("*.py") if p.name != "test_bs.py"]

    return sorted(files)


@pytest.fixture(scope="session")
def ast_trees(target_files):
    """Parse every target file to an AST once for re-use."""
    trees: dict[Path, tuple[ast.Module, str]] = {}
    for file in target_files:
        src = file.read_text(encoding="utf-8")
        trees[file] = (ast.parse(src, filename=str(file)), src)
    return trees


# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#  Static-analysis “outer” tests (flake8 / mypy / bandit)                     #
# --------------------------------------------------------------------------- #
class TestStaticAnalysis:
    def test_flake8(self, target_files, request):
        """Fail if flake8 (plus optional McCabe) reports any error."""
        flake8 = pytest.importorskip("flake8")
        from flake8.api import legacy as flake8_api

        style = flake8_api.get_style_guide(
            max_complexity=request.config.getoption("--max-complexity")
        )
        report = style.check_files([str(f) for f in target_files])
        assert (
            report.total_errors == 0
        ), "flake8 violations found—run `flake8` for details"

    def test_mypy(self, request):
        """Optional mypy run if --run-mypy was supplied."""
        if not request.config.getoption("--run-mypy"):
            pytest.skip("mypy run skipped (enable with --run-mypy)")
        from mypy import api as mypy_api

        target = str(Path(request.config.getoption("--script")))
        stdout, stderr, exit_ = mypy_api.run([target, "--ignore-missing-imports"])
        assert exit_ == 0, f"mypy type errors:\n{stdout or stderr}"

    def test_bandit(self, request):
        """Optional Bandit security scan if --run-bandit was supplied."""
        if not request.config.getoption("--run-bandit"):
            pytest.skip("Bandit run skipped (enable with --run-bandit)")
        pytest.importorskip("bandit")

        root = Path(request.config.getoption("--script"))
        cmd = ["bandit", "-q"]
        cmd += ["-r", str(root)] if root.is_dir() else [str(root)]

        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, f"Bandit issues:\n{res.stdout or res.stderr}"


# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
#  Quality-of-code tests (NASA-inspired + practical checks)                   #
# --------------------------------------------------------------------------- #
class TestCodeQuality:
    # 1 --­­ function length -------------------------------------------------- #
    def test_function_length(self, ast_trees, request):
        max_len = request.config.getoption("--max-func-lines")
        offenders = []
        for path, (tree, _) in ast_trees.items():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    end = getattr(node, "end_lineno", node.lineno)
                    if end - node.lineno + 1 > max_len:
                        offenders.append(
                            f"{node.name} in {path.name} ({end - node.lineno + 1} lines)"
                        )
        assert not offenders, "Functions too long:\n" + "\n".join(offenders)

    # 2 --­­ assertion density ------------------------------------------------ #
    def test_assertion_density(self, ast_trees, request):
        strict = request.config.getoption("--strict")
        needed = 2.0 if strict else 1.0
        total_as = total_fn = 0
        no_assert = []

        for path, (tree, _) in ast_trees.items():
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    total_fn += 1
                    n = sum(isinstance(x, ast.Assert) for x in ast.walk(fn))
                    total_as += n
                    if n == 0:
                        no_assert.append(f"{fn.name} in {path.name}")

        avg = total_as / total_fn if total_fn else 0
        assert avg >= needed, f"Average asserts/function {avg:.2f} < {needed}"
        if strict:
            assert not no_assert, "No assertions in:\n" + "\n".join(no_assert)

    # 3 --­­ mutable default args -------------------------------------------- #
    def test_mutable_defaults(self, ast_trees):
        bad = []
        for path, (tree, _) in ast_trees.items():
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if any(
                        isinstance(d, (ast.List, ast.Dict, ast.Set))
                        for d in fn.args.defaults
                    ):
                        bad.append(f"{fn.name} in {path.name}")
        assert not bad, "Mutable default arguments:\n" + "\n".join(bad)

    # 4 --­­ inconsistent returns -------------------------------------------- #
    def test_return_consistency(self, ast_trees):
        offenders = []
        for path, (tree, _) in ast_trees.items():
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if any(
                        isinstance(x, (ast.Yield, ast.YieldFrom)) for x in ast.walk(fn)
                    ):
                        continue  # generators handled elsewhere
                    returns = [r for r in ast.walk(fn) if isinstance(r, ast.Return)]
                    if not returns:
                        continue
                    has_val = any(r.value is not None for r in returns)
                    has_none = any(r.value is None for r in returns)
                    if has_val and has_none:
                        offenders.append(f"{fn.name} in {path.name}")
        assert not offenders, "Inconsistent return paths:\n" + "\n".join(offenders)

    # 5 --­­ input validation (guard clauses) -------------------------------- #
    def test_input_validation(self, ast_trees, request):
        strict = request.config.getoption("--strict")
        misses = []

        for path, (tree, _) in ast_trees.items():
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    params = [a.arg for a in fn.args.args + fn.args.kwonlyargs]
                    if params and params[0] in ("self", "cls"):
                        params = params[1:]
                    if not params:
                        continue

                    validated = False
                    for stmt in fn.body[:5]:  # heuristic: first 5 stmts
                        if isinstance(stmt, ast.Assert) and any(
                            isinstance(x, ast.Name) and x.id in params
                            for x in ast.walk(stmt.test)
                        ):
                            validated = True
                            break
                        if isinstance(stmt, ast.If) and any(
                            isinstance(x, ast.Name) and x.id in params
                            for x in ast.walk(stmt.test)
                        ):
                            validated = True
                            break

                    long_fn = (getattr(fn, "end_lineno", fn.lineno) - fn.lineno + 1) > 3
                    if (strict and not validated) or (
                        not strict and long_fn and not validated
                    ):
                        misses.append(f"{fn.name} in {path.name}")

        assert not misses, "Missing param checks:\n" + "\n".join(misses)

    # 6 --­­ sketchy boolean / None comparisons ------------------------------ #
    def test_sketchy_comparisons(self, ast_trees):
        bad = []
        for path, (tree, _) in ast_trees.items():
            for cmp in (n for n in ast.walk(tree) if isinstance(n, ast.Compare)):
                left = cmp.left
                for op, right in zip(cmp.ops, cmp.comparators):
                    for side in (left, right):
                        if isinstance(side, ast.Constant):
                            val = side.value
                            if val is None and isinstance(op, (ast.Eq, ast.NotEq)):
                                bad.append(f"{path.name}:{cmp.lineno} uses '== None'")
                            if val in (True, False):
                                bad.append(
                                    f"{path.name}:{cmp.lineno} boolean literal comparison"
                                )
                    left = right
        assert not bad, "Sketchy comparisons:\n" + "\n".join(bad)

    # 7 --­­ dead code “if False:” blocks ------------------------------------ #
    def test_dead_code_blocks(self, ast_trees):
        dead = []
        for path, (tree, _) in ast_trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
                    if node.test.value in (False, 0, None):
                        dead.append(
                            f"{path.name}:{node.lineno} unreachable 'if {node.test.value}:'"
                        )
        assert not dead, "Dead code blocks:\n" + "\n".join(dead)

    # 8 --­­ unused variables ------------------------------------------------- #
    def test_unused_variables(self, ast_trees):
        unused = []
        for path, (tree, _) in ast_trees.items():
            assigns, uses = {}, set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            assigns[tgt.id] = node.lineno
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    uses.add(node.id)
            for var, ln in assigns.items():
                if var not in uses and not var.startswith("_"):
                    unused.append(f"{path.name}:{ln} '{var}' assigned but unused")
        assert not unused, "Unused variables:\n" + "\n".join(unused)

    # 9 --­­ wildcard imports ------------------------------------------------- #
    def test_wildcard_imports(self, ast_trees):
        offenders = []
        for path, (tree, _) in ast_trees.items():
            for imp in (n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)):
                if imp.names and imp.names[0].name == "*":
                    offenders.append(
                        f"{path.name}:{imp.lineno} wildcard import from '{imp.module}'"
                    )
        assert not offenders, "Wildcard imports:\n" + "\n".join(offenders)

    # 10 --­­ exec / eval ban ------------------------------------------------- #
    def test_no_exec_or_eval(self, ast_trees):
        danger = []
        for path, (tree, _) in ast_trees.items():
            for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
                if isinstance(call.func, ast.Name) and call.func.id in {"exec", "eval"}:
                    danger.append(f"{path.name}:{call.lineno} uses {call.func.id}()")
        assert not danger, "exec/eval usage:\n" + "\n".join(danger)


# --------------------------------------------------------------------------- #
