import ast
import pytest
import os
import subprocess
import sys
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional


# Function to parse command-line options using pytest_addoption
def pytest_addoption(parser):
    parser.addoption(
        "--script",
        action="store",
        help="Path to python script or package directory to analyze",
    )
    parser.addoption(
        "--strict",
        action="store_true",
        default=False,
        help="Bool flag – if present, tighten several rules",
    )
    parser.addoption(
        "--max-func-lines",
        action="store",
        type=int,
        default=50,
        help="Maximum allowed lines per function (default to 50)",
    )
    parser.addoption(
        "--run-mypy",
        action="store_true",
        default=False,
        help="Bool flag – if present, run mypy on the target",
    )
    parser.addoption(
        "--run-bandit",
        action="store_true",
        default=False,
        help="Bool flag – if present, run bandit on the target",
    )
    parser.addoption(
        "--max-complexity",
        action="store",
        type=int,
        default=10,
        help="Max cyclomatic complexity for flake8-mccabe",
    )


@pytest.fixture(scope="session")
def script_path(request):
    return request.config.getoption("--script")


@pytest.fixture(scope="session")
def strict_mode(request):
    return request.config.getoption("--strict")


@pytest.fixture(scope="session")
def max_func_lines(request):
    return request.config.getoption("--max-func-lines")


@pytest.fixture(scope="session")
def run_mypy(request):
    return request.config.getoption("--run-mypy")


@pytest.fixture(scope="session")
def run_bandit(request):
    return request.config.getoption("--run-bandit")


@pytest.fixture(scope="session")
def max_complexity(request):
    return request.config.getoption("--max-complexity")


@pytest.fixture(scope="session")
def python_files(script_path):
    """Collect *.py files recursively if script_path is a directory."""
    py_files = []
    if os.path.isfile(script_path) and script_path.endswith(".py"):
        py_files.append(script_path)
    elif os.path.isdir(script_path):
        for root, dirs, files in os.walk(script_path):
            for file in files:
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))
    else:
        raise ValueError(
            f"Provided path {script_path} is neither a single .py file nor a directory."
        )
    return py_files


@pytest.fixture(scope="session")
def ast_trees(python_files) -> Dict[str, ast.AST]:
    ast_map = {}
    for py_file in python_files:
        with open(py_file, "r") as file:
            source_code = file.read()
            ast_map[py_file] = ast.parse(source_code, filename=py_file)
    return ast_map


@pytest.fixture(scope="session")
def source_codes(python_files) -> Dict[str, str]:
    source_map = {}
    for py_file in python_files:
        with open(py_file, "r") as file:
            source_map[py_file] = file.read()
    return source_map


class FuncAnalysisVisitor(ast.NodeVisitor):
    def __init__(
        self,
        strict_mode: bool,
        max_func_lines: int,
        max_complexity: int,
    ):
        self.strict_mode = strict_mode
        self.max_func_lines = max_func_lines
        self.max_complexity = max_complexity
