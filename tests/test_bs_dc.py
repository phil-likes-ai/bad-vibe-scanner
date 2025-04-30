import ast
import sys
import os
from pathlib import Path
import pytest
from flake8.api import legacy as flake8
from flake8.style_guide import StyleGuide

# Import optional tools with pytest's import skipping
mypy = pytest.importorskip("mypy")
bandit = pytest.importorskip("bandit")

# Fixtures to collect files and build AST


@pytest.fixture(scope="session")
def all_python_files(script_path):
    """Collect all .py files under the script path, recursively."""
    paths = []
    if script_path.is_dir():
        for PythonFile in script_path.rglob("*.py"):
            paths.append(str(PythonFile))
    else:
        if script_path.suffix == ".py":
            paths.append(str(script_path))
    return paths


@pytest.fixture(scope="session")
def collected_files(request, all_python_files):
    return all_python_files


@pytest.fixture(scope="session")
def ast_trees(collected_files):
    """Build AST trees and keep original source for each file."""
    trees = []
    for file in collected_files:
        with open(file, "r", encoding="utf-8") as f:
            src = f.read()
            tree = ast.parse(src)
            trees.append((file, src, tree))
    return trees


# Static analysis tests


def test_flake8_compliance(ast_trees, script):
    """Run flake8 with max complexity limit."""
    style = StyleGuide()
    reporter = style.get_reporter()
    for file, _, _ in ast_trees:
        runner = flake8.runners.persistent._Runner(
            reporter, file, file, None, None, None
        )
        runner.run()
        # Check complexity based on --max-complexity
        # (Note: Flak8's McCabe plugin is required for complexity)


def test_mypy_compliance(mypy, ast_trees, script, request):
    """Run mypy if enabled."""
    if request.config.getoption("--run-mypy"):
        for file, src, _ in ast_trees:
            # TODO: Implement mypy checks
            pass


def test_bandit_compliance(bandit, ast_trees, script, request):
    """Run bandit if enabled."""
    if request.config.getoption("--run-bandit"):
        for file, src, _ in ast_trees:
            # TODO: Implement bandit security checks
            pass


# Code quality tests


def test_function_length(ast_trees, strict, max_func_lines):
    """Check function lengths."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Calculate line count
                lines = node.lineno + len(node.body) - 1
                if lines > max_func_lines:
                    assert False, f"Function exceeds {max_func_lines} lines"


def test_assertion_density(ast_trees, strict):
    """Check assertion density per function."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Count asserts and parameters
                assert_count = 0
                for n in ast.walk(node):
                    if isinstance(n, ast.Assert):
                        assert_count += 1
                params = [arg.name for arg in node.args.args]
                if len(params) > 0 or strict:
                    if strict:
                        assert assert_count >= 2, "Insufficient assertions"
                    else:
                        assert assert_count >= 1, "Insufficient assertions"


def test_mutable_defaults(ast_trees):
    """Check for mutable default arguments."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.args:
                    default = arg.default
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        assert False, "Mutable default argument found"


def test_parameter_validation(ast_trees, strict):
    """Check for parameter validation."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if len(node.args.args) > 0:
                    # Check first few lines for param usage
                    # (Simplified check)
                    has_param = False
                    for n in ast.iter_child_nodes(node):
                        if isinstance(n, ast.Compare) or isinstance(n, ast.Assign):
                            if any(
                                arg.id in [a.name for a in node.args.args]
                                for arg in ast.walk(n)
                            ):
                                has_param = True
                                break
                    if not has_param and (strict or len(node.body) > 3):
                        assert False, "Missing parameter validation"


def test_prohibited_comparisons(ast_trees):
    """Check for prohibited comparisons."""
    prohibited = {"None", "True", "False", "is", "==", "!="}
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                op_str = ast.unparse(node.ops[0])
                if op_str in prohibited:
                    assert False, f"Prohibited comparison operator: {op_str}"


def test_unused_locals(ast_trees):
    """Check for unused local variables."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                target = node.target.id
                # Check if target is ever loaded
                if not any(
                    isinstance(n, ast.Name) and n.id == target
                    for n in ast.walk(tree)
                    if isinstance(n, ast.Load)
                ):
                    assert False, f"Unused local variable: {target}"


def test_wildcard_imports(ast_trees):
    """Check for wildcard imports."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(alias.asname == "*" for alias in node.names):
                    assert False, "Wildcard import detected"


def test_exec_eval_calls(ast_trees):
    """Check for exec() or eval() calls."""
    for _, src, tree in ast_trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval"):
                    assert False, "exec() or eval() detected"


# Mark all tests as part of the code hygiene suite
@pytest.mark.code_hygiene
def test_suite():
    pass


# Add option parsing
def pytest_addoption(parser):
    parser.addoption(
        "--script",
        action="store",
        required=True,
        help="Path to .py file or package directory",
    )
    parser.addoption("--strict", action="store_true", help="Tighten several rules")
    parser.addoption(
        "--max-func-lines",
        action="store",
        type="int",
        default=50,
        help="Max allowed lines per function",
    )
    parser.addoption("--run-mypy", action="store_true", help="Run Mypy on the target")
    parser.addoption(
        "--run-bandit", action="store_true", help="Run Bandit on the target"
    )
    parser.addoption(
        "--max-complexity", action="store", type="int", help="Max cyclomatic complexity"
    )


# Set up fixtures
def test_path(script, collected_files):
    assert len(collected_files) > 0, "No Python files found"


# Ensure all code is PEP8 compliant and runs with pytest
if __name__ == "__main__":
    sys.exit(pytest.main())
