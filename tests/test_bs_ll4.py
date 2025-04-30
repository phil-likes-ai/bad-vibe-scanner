# test_bs.py
import ast
import os
import subprocess
import pytest


def pytest_addoption(parser):
    """Add command-line options."""
    parser.addoption(
        "--script", help="Path to a .py file or a package directory to analyse"
    )
    parser.addoption(
        "--strict",
        action="store_true",
        help="Bool flag – if present, tighten several rules",
    )
    parser.addoption(
        "--max-func-lines",
        type=int,
        default=50,
        help="Int – maximum allowed lines per function",
    )
    parser.addoption(
        "--run-mypy",
        action="store_true",
        help="Bool flag – if present, run Mypy on the target",
    )
    parser.addoption(
        "--run-bandit",
        action="store_true",
        help="Bool flag – if present, run Bandit on the target",
    )
    parser.addoption(
        "--max-complexity",
        type=int,
        help="Int – max cyclomatic complexity for flake8-mccabe",
    )


@pytest.fixture(scope="session")
def config(request):
    """Return the configuration."""
    return {
        "script": request.config.getoption("--script"),
        "strict": request.config.getoption("--strict"),
        "max_func_lines": request.config.getoption("--max-func-lines"),
        "run_mypy": request.config.getoption("--run-mypy"),
        "run_bandit": request.config.getoption("--run-bandit"),
        "max_complexity": request.config.getoption("--max-complexity"),
    }


@pytest.fixture(scope="session")
def files(config):
    """Collect all *.py files under --script (recursively if directory)."""
    script = config["script"]
    if os.path.isfile(script):
        yield [script]
    else:
        py_files = []
        for root, _, files in os.walk(script):
            for file in files:
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))
        yield py_files


@pytest.fixture(scope="session")
def ast_trees(files):
    """Build an AST tree and keep the original source for each file once."""
    trees = {}
    for file in files:
        with open(file, "r") as f:
            src = f.read()
            tree = ast.parse(src)
            trees[file] = (tree, src)
    yield trees


def test_flake8(config, files):
    """Run flake8."""
    flake8 = pytest.importorskip("flake8")
    max_complexity = config["max_complexity"]
    args = ["--max-complexity", str(max_complexity)] if max_complexity else []
    args.extend(files)
    result = subprocess.run(["flake8"] + args)
    assert result.returncode == 0


def test_mypy(config, files):
    """Run mypy (optional)."""
    if not config["run_mypy"]:
        pytest.skip("Mypy is not enabled")
    mypy = pytest.importorskip("mypy")
    result = subprocess.run(["mypy"] + files)
    assert result.returncode == 0


def test_bandit(config, files):
    """Run bandit (optional)."""
    if not config["run_bandit"]:
        pytest.skip("Bandit is not enabled")
    bandit = pytest.importorskip("bandit")
    result = subprocess.run(["bandit", "-r"] + files)
    assert result.returncode == 0


def test_function_length(config, ast_trees):
    """Function length > --max-func-lines."""
    max_func_lines = config["max_func_lines"]
    for file, (tree, src) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_lines = count_func_lines(node, src)
                assert (
                    func_lines <= max_func_lines
                ), f"Function {node.name} in {file} has {func_lines} lines (max {max_func_lines})"


def count_func_lines(node, src):
    """Count the number of lines in a function."""
    lines = src.splitlines()
    start = node.lineno - 1
    end = node.end_lineno
    return len(lines[start:end])


def test_assertion_density(config, ast_trees):
    """Assertion density: avg ≥ 1 per function (≥ 2 when --strict)."""
    strict = config["strict"]
    min_assertions = 2 if strict else 1
    for file, (tree, _) in ast_trees.items():
        func_assertions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                assertions = count_assertions(node)
                func_assertions.append(assertions)
        avg_assertions = (
            sum(func_assertions) / len(func_assertions) if func_assertions else 0
        )
        assert (
            avg_assertions >= min_assertions
        ), f"Average assertion density in {file} is {avg_assertions} (min {min_assertions})"


def count_assertions(node):
    """Count the number of assertions in a function."""
    count = 0
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Assert):
            count += 1
    return count


def test_mutable_default_args(ast_trees):
    """No mutable default args (list / dict / set)."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.defaults:
                    if isinstance(arg, (ast.List, ast.Dict, ast.Set)):
                        assert (
                            False
                        ), f"Mutable default argument in function {node.name} in {file}"


def test_mixed_return_values(ast_trees):
    """No mixed “return value” *and* bare “return/implicit None” in same func."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                return_values = []
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Return):
                        if subnode.value:
                            return_values.append(True)
                        else:
                            return_values.append(False)
                if len(set(return_values)) > 1:
                    assert (
                        False
                    ), f"Mixed return values in function {node.name} in {file}"


def test_parameter_validation(config, ast_trees):
    """Parameter validation: every func with real parameters must have an early assert/if check that touches one of those params."""
    strict = config["strict"]
    for file, (tree, src) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                if len(node.args.args) > 0:
                    if strict or count_func_lines(node, src) > 3:
                        has_validation = False
                        for subnode in ast.walk(node):
                            if isinstance(subnode, (ast.Assert, ast.If)):
                                for arg in node.args.args:
                                    if ast.unparse(arg) in ast.unparse(subnode):
                                        has_validation = True
                                        break
                                if has_validation:
                                    break
                        assert (
                            has_validation
                        ), f"Function {node.name} in {file} is missing parameter validation"


def test_comparisons(ast_trees):
    """No comparisons `== None`, `!= None`, `== True/False`, `is True/False`."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op in node.ops:
                    if (
                        isinstance(op, (ast.Eq, ast.NotEq))
                        and isinstance(node.comparators[0], ast.Constant)
                        and node.comparators[0].value is None
                    ):
                        assert False, f"Comparison with None in {file}"
                    elif (
                        isinstance(op, (ast.Eq, ast.Is, ast.IsNot))
                        and isinstance(node.comparators[0], ast.Constant)
                        and node.comparators[0].value in (True, False)
                    ):
                        assert False, f"Comparison with True/False in {file}"


def test_if_false(ast_trees):
    """No `if False:` / `if 0:` / `if None:` blocks."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.Constant) and node.test.value in (
                    False,
                    0,
                    None,
                ):
                    assert False, f"If statement with constant False/0/None in {file}"


def test_unused_locals(ast_trees):
    """No unused local variables (heuristic: assigned once, never loaded)."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                assigned = set()
                loaded = set()
                for subnode in ast.walk(node):
                    if isinstance(subnode, ast.Assign):
                        for target in subnode.targets:
                            if isinstance(target, ast.Name):
                                assigned.add(target.id)
                    elif isinstance(subnode, ast.Name) and isinstance(
                        subnode.ctx, ast.Load
                    ):
                        loaded.add(subnode.id)
                unused = assigned - loaded
                assert (
                    not unused
                ), f"Unused local variables {unused} in function {node.name} in {file}"


def test_wildcard_imports(ast_trees):
    """No wildcard imports (`from x import *`)."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.names[0].name == "*":
                assert False, f"Wildcard import in {file}"


def test_exec_eval(ast_trees):
    """No calls to `exec()` or `eval()`."""
    for file, (tree, _) in ast_trees.items():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("exec", "eval")
            ):
                assert False, f"Call to {node.func.id}() in {file}"
