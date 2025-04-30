import ast
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import pytest
from pytest import fixture


# Command-line option handling
def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--script",
        action="store",
        required=True,
        help="Path to a .py file or package directory",
    )
    parser.addoption("--strict", action="store_true", help="Tighten several rules")
    parser.addoption(
        "--max-func-lines",
        type=int,
        default=50,
        help="Maximum allowed lines per function",
    )
    parser.addoption("--run-mypy", action="store_true", help="Run Mypy on the target")
    parser.addoption(
        "--run-bandit", action="store_true", help="Run Bandit on the target"
    )
    parser.addoption(
        "--max-complexity", type=int, help="Max cyclomatic complexity for flake8-mccabe"
    )


# Fixtures
@fixture(scope="session")
def files(request: pytest.FixtureRequest) -> List[Path]:
    script_path = Path(request.config.getoption("--script"))
    if script_path.is_file():
        return [script_path]
    elif script_path.is_dir():
        return list(script_path.rglob("*.py"))
    else:
        pytest.fail("--script must be a valid file or directory")


@fixture(scope="session")
def ast_trees(files: List[Path]) -> Dict[Path, ast.AST]:
    trees = {}
    for file in files:
        with open(file, "r") as f:
            source = f.read()
            try:
                tree = ast.parse(source)
                trees[file] = tree
            except SyntaxError as e:
                pytest.fail(f"Syntax error in {file}: {e}")
    return trees


# Static-analysis tests
def test_flake8(files: List[Path], request: pytest.FixtureRequest) -> None:
    max_complexity = request.config.getoption("--max-complexity")
    flake8 = pytest.importorskip("flake8.api.legacy")
    for file in files:
        style_guide = flake8.get_style_guide(
            select=["C", "E", "W", "F"],
            max_complexity=max_complexity,
        )
        result = style_guide.input_file(file)
        if result.total_errors > 0:
            pytest.fail(f"flake8 errors in {file}")


@pytest.mark.run_mypy
def test_mypy(files: List[Path]) -> None:
    mypy = pytest.importorskip("mypy")
    for file in files:
        result = mypy.run([str(file)])
        if result != 0:
            pytest.fail(f"Mypy errors in {file}")


@pytest.mark.run_bandit
def test_bandit(files: List[Path]) -> None:
    bandit = pytest.importorskip("bandit")
    for file in files:
        result = bandit.main([str(file), "--format", "json", "--recursive"])
        if result != 0:
            pytest.fail(f"Bandit errors in {file}")


# Code-quality tests (AST-based)
def test_function_length(
    ast_trees: Dict[Path, ast.AST], request: pytest.FixtureRequest
) -> None:
    max_func_lines = request.config.getoption("--max-func-lines")
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                lines = node.end_lineno - node.lineno + 1
                if lines > max_func_lines:
                    pytest.fail(
                        f"Function {node.name} in {file} exceeds {max_func_lines} lines"
                    )


def test_assertion_density(
    ast_trees: Dict[Path, ast.AST], request: pytest.FixtureRequest
) -> None:
    strict = request.config.getoption("--strict")
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                assertions = sum(
                    1 for child in node.body if isinstance(child, ast.Assert)
                )
                if strict:
                    min_assertions = 2
                else:
                    min_assertions = 1
                if assertions < min_assertions:
                    pytest.fail(
                        f"Function {node.name} in {file} has low assertion density"
                    )


def test_no_mutable_default_args(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                for arg in node.args.defaults:
                    if isinstance(arg, (ast.List, ast.Dict, ast.Set)):
                        pytest.fail(
                            f"Mutable default argument in {node.name} in {file}"
                        )


def test_no_mixed_returns(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                has_return_value = False
                has_bare_return = False
                for child in node.body:
                    if isinstance(child, ast.Return):
                        if child.value is not None:
                            has_return_value = True
                        else:
                            has_bare_return = True
                if has_return_value and has_bare_return:
                    pytest.fail(
                        f"Function {node.name} in {file} has mixed return types"
                    )


def test_parameter_validation(
    ast_trees: Dict[Path, ast.AST], request: pytest.FixtureRequest
) -> None:
    strict = request.config.getoption("--strict")
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                params = node.args.args
                if not params:
                    continue
                if strict or (node.end_lineno - node.lineno + 1) > 3:
                    has_assert = False
                    for child in node.body:
                        if isinstance(child, ast.Assert):
                            for target in ast.walk(child.test):
                                if isinstance(target, ast.Name) and target.id in [
                                    arg.arg for arg in params
                                ]:
                                    has_assert = True
                                    break
                            if has_assert:
                                break
                        elif isinstance(child, ast.If):
                            for target in ast.walk(child.test):
                                if isinstance(target, ast.Name) and target.id in [
                                    arg.arg for arg in params
                                ]:
                                    has_assert = True
                                    break
                            if has_assert:
                                break
                    if not has_assert:
                        pytest.fail(
                            f"Function {node.name} in {file} lacks parameter validation"
                        )


def test_no_invalid_comparisons(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for operand in node.ops:
                    if (
                        isinstance(operand[1], ast.NameConstant)
                        and operand[1].value is None
                    ):
                        pytest.fail(f"Comparison to None in {file}")
                    elif isinstance(operand[1], ast.NameConstant) and operand[
                        1
                    ].value in (True, False):
                        pytest.fail(f"Comparison to True/False in {file}")
                    elif (
                        isinstance(operand[0], ast.NameConstant)
                        and operand[0].value is None
                    ):
                        pytest.fail(f"Comparison to None in {file}")
                    elif isinstance(operand[0], ast.NameConstant) and operand[
                        0
                    ].value in (True, False):
                        pytest.fail(f"Comparison to True/False in {file}")


def test_no_if_blocks(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                if isinstance(node.test, ast.NameConstant) and node.test.value in (
                    False,
                    0,
                    None,
                ):
                    pytest.fail(f"Invalid if block in {file}")


def test_no_unused_locals(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        locals: Set[str] = set()
        used: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        locals.add(target.id)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used.add(node.id)
        unused = locals - used
        if unused:
            pytest.fail(f"Unused locals in {file}: {unused}")


def test_no_wildcard_imports(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.names[0].name == "*":
                pytest.fail(f"Wildcard import in {file}")


def test_no_exec_eval(ast_trees: Dict[Path, ast.AST]) -> None:
    for file, tree in ast_trees.items():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("exec", "eval")
            ):
                pytest.fail(f"exec/eval call in {file}")
