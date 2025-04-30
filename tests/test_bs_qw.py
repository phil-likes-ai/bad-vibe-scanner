import ast
import os
import sys
from collections import defaultdict
from typing import List, Dict, Set, Union, Tuple

import pytest


@pytest.fixture(scope="session")
def script_files(request) -> List[str]:
    script_path = request.config.getoption("--script")
    if os.path.isdir(script_path):
        return [
            os.path.join(dirpath, f)
            for dirpath, _, filenames in os.walk(script_path)
            for f in filenames
            if f.endswith(".py")
        ]
    elif os.path.isfile(script_path):
        return [script_path]
    else:
        pytest.fail(f"Invalid path provided: {script_path}")


@pytest.fixture(scope="session")
def ast_trees_and_sources(script_files) -> List[Tuple[ast.AST, str]]:
    trees_and_sources = []
    for file_path in script_files:
        with open(file_path, "r") as file:
            source = file.read()
        tree = ast.parse(source)
        trees_and_sources.append((tree, source))
    return trees_and_sources


def pytest_addoption(parser):
    parser.addoption("--strict", action="store_true", help="Enable strict mode")
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
    parser.addoption(
        "--script",
        required=True,
        help="Path to a .py file or a package directory to analyse",
    )


def check_function_length(tree, max_func_lines):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            lines = len(ast.get_source_segment(tree, node).splitlines())
            if lines > max_func_lines:
                return (
                    False,
                    f"Function '{node.name}' exceeds max lines: {lines} > {max_func_lines}",
                )
    return True, ""


def check_assertion_density(tree, strict_mode):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assertion_count = sum(isinstance(n, ast.Assert) for n in ast.walk(node))
            if strict_mode and (assertion_count < 2):
                return False, f"Function '{node.name}' has less than 2 assertions"
            if not strict_mode and (assertion_count < 1):
                return False, f"Function '{node.name}' has no assertions"
    return True, ""


def check_no_mutable_defaults(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for arg in node.args.defaults:
                if isinstance(arg, (ast.List, ast.Dict, ast.Set)):
                    return False, f"Mutable default arg in function '{node.name}'"
    return True, ""


def check_no_mixed_returns(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            return_types = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Return):
                    if child.value is None:
                        return_types.add(None)
                    else:
                        return_types.add(type(child.value))
            if len(return_types) > 1:
                return False, f"Function '{node.name}' has mixed return types"
    return True, ""


def check_parameter_validation(tree, strict_mode):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if strict_mode or len(node.body) > 3:
                if not any(
                    isinstance(n, (ast.Assert, ast.If))
                    and any(
                        isinstance(child, ast.Name)
                        and child.id in [a.arg for a in node.args.args]
                        for child in ast.walk(n)
                    )
                    for n in node.body
                ):
                    return False, f"Function '{node.name}' lacks parameter validation"
    return True, ""


def check_no_prohibited_comparisons(tree):
    prohibited_comparisons = {
        ("Compare", "Eq", "None"),
        ("Compare", "NotEq", "None"),
        ("Compare", "Eq", "NameConstant"),
        ("Compare", "NotEq", "NameConstant"),
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            opcode = node.ops[0]
            if (
                type(node.left).__name__,
                type(opcode).__name__,
                type(node.comparators[0]).__name__,
            ) in prohibited_comparisons:
                return False, "Prohibited comparison found"
    return True, ""


def check_no_invalid_if_statements(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            if isinstance(
                node.test, (ast.Constant, ast.NameConstant)
            ) and node.test.value in (False, 0, None):
                return False, "Invalid 'if' statement found"
    return True, ""


def check_no_unused_vars(tree):
    assigned_vars = set()
    used_vars = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            assigned_vars.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used_vars.add(node.id)

    unused_vars = assigned_vars - used_vars
    if unused_vars:
        return False, f"Unused variables found: {unused_vars}"
    return True, ""


def check_no_wildcard_imports(tree):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "*"
            or any(
                isinstance(alias, ast.alias) and alias.name == "*"
                for alias in node.names
            )
        ):
            return False, "Wildcard import found"
    return True, ""


def check_no_exec_eval(tree):
    prohibited_functions = {"exec", "eval"}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in prohibited_functions
        ):
            return False, f"Call to prohibited function '{node.func.id}' found"
    return True, ""


@pytest.mark.parametrize(
    "checker_function",
    [
        check_function_length,
        lambda tree, strict_mode: check_assertion_density(tree, strict_mode),
        check_no_mutable_defaults,
        check_no_mixed_returns,
        lambda tree, strict_mode: check_parameter_validation(tree, strict_mode),
        check_no_prohibited_comparisons,
        check_no_invalid_if_statements,
        check_no_unused_vars,
        check_no_wildcard_imports,
        check_no_exec_eval,
    ],
)
def test_code_quality(script_files, ast_trees_and_sources, checker_function, request):
    strict_mode = request.config.getoption("--strict")
    max_func_lines = request.config.getoption("--max-func-lines")

    for tree, _ in ast_trees_and_sources:
        result, message = checker_function(
            tree,
            strict_mode=(
                strict_mode
                if checker_function != check_function_length
                else max_func_lines
            ),
        )
        if not result:
            pytest.fail(message, pytrace=False)


def run_external_tool(tool_name, script_files, **kwargs):
    tool = pytest.importorskip(tool_name)
    tool.main(["--", *script_files, *kwargs.items()])


@pytest.mark.skipif(
    not pytest.config.getoption("--run-mypy"), reason="--run-mypy not set"
)
def test_mypy(script_files):
    run_external_tool("mypy", script_files)


@pytest.mark.skipif(
    not pytest.config.getoption("--run-bandit"), reason="--run-bandit not set"
)
def test_bandit(script_files):
    run_external_tool("bandit", script_files)


def test_flake8(script_files, request):
    max_complexity = request.config.getoption("--max-complexity")
    additional_args = []
    if max_complexity is not None:
        additional_args += ["--max-complexity", str(max_complexity)]
    run_external_tool("flake8", script_files, *additional_args)
