import os
import sys
from pathlib import Path
import ast
import pytest
from typing import List, Dict, Optional


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add command-line options for Pytest."""
    parser.addoption("--script", type=str, help="Path to a .py file or a package directory", required=True)
    parser.addoption("--strict", action="store_true", help="Enforce stricter rules")
    parser.addoption("--max-func-lines", type=int, default=50, help="Maximum allowed lines per function")
    parser.addoption("--run-mypy", action="store_true", help="Run Mypy on the target")
    parser.addoption("--run-bandit", action="store_true", help="Run Bandit on the target")
    parser.addoption("--max-complexity", type=int, help="Max cyclomatic complexity for flake8-mccabe")


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Generate test cases from --script option."""
    if "target_files" in metafunc.fixturenames:
        script_path = metafunc.config.getoption("--script")
        if script_path.endswith(".py"):
            target_files = [Path(script_path)]
        else:
            target_files = []
            for root, _, files in os.walk(script_path):
                for file in files:
                    if file.endswith(".py"):
                        target_files.append(Path(os.path.join(root, file)))
        metafunc.parametrize("target_files", [target_files], scope="session")


@pytest.fixture(scope="session")
def ast_trees(target_files: List[Path]) -> Dict[Path, ast.AST]:
    """Parse and return AST trees for all target files."""
    ast_trees = {}
    for file_path in target_files:
        with open(file_path, "r", encoding="utf-8") as file:
            source = file.read()
            try:
                ast_trees[file_path] = ast.parse(source)
            except SyntaxError as e:
                pytest.fail(f"Failed to parse {file_path} due to syntax error: {e}", pytrace=False)
    return ast_trees


def run_flake8(file_path: Path, max_complexity: Optional[int]) -> None:
    """Run flake8 and fail if errors are found."""
    flake8 = pytest.importorskip("flake8")
    import flake8.api.legacy as legacy

    style_guide = legacy.get_style_guide(max_complexity=max_complexity)
    report = style_guide.check_files([str(file_path)])
    if report.total_errors > 0:
        pytest.fail(f"flake8 found errors in {file_path}", pytrace=False)


def run_mypy(file_path: Path) -> None:
    """Run mypy and fail if errors are found."""
    mypy = pytest.importorskip("mypy")
    from mypy import build

    try:
        build.build(
            show_traceback=True,
            python_version=sys.version_info[:2],
            sources=[str(file_path)],
            options=build.BuildOptions(),
        )
    except Exception as e:
        pytest.fail(f"mypy failed on {file_path}: {e}", pytrace=False)


def run_bandit(file_path: Path) -> None:
    """Run bandit and fail if high or medium issues are found."""
    bandit = pytest.importorskip("bandit")
    from bandit.core import config, manager

    cfg = config.Config()
    b_mgr = manager.BanditManager(cfg)
    scan_results = b_mgr.execute_file(str(file_path))
    if scan_results.score > 0:
        pytest.fail(f"bandit found issues in {file_path}", pytrace=False)


def check_function_length(node: ast.FunctionDef, max_func_lines: int) -> None:
    """Fail if a function exceeds the maximum line length."""
    start = node.lineno
    end = node.end_lineno
    num_lines = end - start + 1
    if num_lines > max_func_lines:
        pytest.fail(f"Function {node.name} exceeds {max_func_lines} lines ({num_lines})", pytrace=False)


def check_assertion_density(node: ast.FunctionDef, strict: bool) -> None:
    """Fail if assertion density is too low."""
    assertions = sum(1 for n in ast.walk(node) if isinstance(n, ast.Assert))
    required_assertions = 2 if strict else 1
    min_lines = 3 if strict else 5
    if len(node.body) >= min_lines and assertions < required_assertions:
        pytest.fail(f"Function {node.name} has low assertion density ({assertions} < {required_assertions})", pytrace=False)


def check_mutable_default_args(node: ast.FunctionDef) -> None:
    """Fail if a function has mutable default arguments."""
    for arg in node.args.defaults:
        if isinstance(arg, (ast.List, ast.Dict, ast.Set)):
            pytest.fail(f"Function {node.name} has mutable default argument", pytrace=False)


def check_mixed_returns(node: ast.FunctionDef) -> None:
    """Fail if a function mixes return values with bare returns."""
    has_value_return = any(isinstance(n, ast.Return) and n.value is not None for n in node.body)
    has_bare_return = any(isinstance(n, ast.Return) and n.value is None for n in node.body)
    if has_value_return and has_bare_return:
        pytest.fail(f"Function {node.name} mixes value and bare returns", pytrace=False)


def check_parameter_validation(node: ast.FunctionDef, strict: bool) -> None:
    """Fail if a function with parameters lacks early parameter validation."""
    if strict or len(node.args.args) + len(node.args.kwonlyargs) > 3:
        has_validation = False
        for n in node.body[:5]:  # Check first few lines for validation
            if isinstance(n, (ast.Assert, ast.If)) and any(
                isinstance(e, ast.Name) and e.id in [arg.arg for arg in node.args.args if arg.arg != "self"]
                for e in ast walk(n) if isinstance(e, ast.expr)
            ):
                has_validation = True
                break
        if not has_validation:
            pytest.fail(f"Function {node.name} lacks early parameter validation", pytrace=False)


def check_comparisons(node: ast.FunctionDef) -> None:
    """Fail if forbidden comparisons are used."""
    forbidden = ["== None", "!= None", "== True", "== False", "is True", "is False"]
    for n in ast.walk(node):
        if isinstance(n, ast.Compare):
            for op in n.ops:
                if (
                    isinstance(op, ast.Eq) and any(isinstance(x, ast.Name) and x.id in forbidden for x in n.left)
                    or isinstance(op, ast.NotEq) and any(isinstance(x, ast.Name) and x.id in forbidden for x in n.left)
                    or isinstance(op, ast.Is) and any(isinstance(x, ast.Name) and x.id in forbidden for x in n.left)
                    or isinstance(op, ast.IsNot) and any(isinstance(x, ast.Name) and x.id in forbidden for x in n.left)
                ):
                    pytest.fail(f"Function {node.name} uses forbidden comparison {op}", pytrace=False)


def check_if_false(node: ast.FunctionDef) -> None:
    """Fail if `if False:` or similar is found."""
    for n in ast.walk(node):
        if isinstance(n, ast.If) and isinstance(n.test, ast.Constant) and n.test.value in [False, 0, None]:
            pytest.fail(f"Function {node.name} contains an unrelated `if False:` block", pytrace=False)


def check_unused_variables(node: ast.FunctionDef) -> None:
    """Fail if local variables appear to be unused."""
    assigned = set()
    used = set()
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Name) and isinstance(subnode.ctx, ast.Store):
            assigned.add(subnode.id)
        elif isinstance(subnode, ast.Name) and isinstance(subnode.ctx, ast.Load):
            used.add(subnode.id)
    unused = assigned - used
    if unused:
        pytest.fail(f"Function {node.name} has unused variables: {', '.join(unused)}", pytrace=False)


def check_wildcard_imports(node: ast.FunctionDef) -> None:
    """Fail if wildcard imports are found."""
    for n in ast.walk(node):
        if isinstance(n, ast.ImportFrom) and n.names[0].name == "*":
            pytest.fail(f"Function {node.name} contains a wildcard import", pytrace=False)


def check_exec_eval(node: ast.FunctionDef) -> None:
    """Fail if exec() or eval() is called."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in {"exec", "eval"}:
            pytest.fail(f"Function {node.name} contains a call to {n.func.id}", pytrace=False)


def check_ast_tree(file_path: Path, ast_tree: ast.AST, max_func_lines: int, strict: bool) -> None:
    """Run all AST-based checks on a file."""
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.FunctionDef):
            check_function_length(node, max_func_lines)
            check_assertion_density(node, strict)
            check_mutable_default_args(node)
            check_mixed_returns(node)
            check_parameter_validation(node, strict)
            check_unused_variables(node)
            check_wildcard_imports(node)
            check_exec_eval(node)
    for node in ast.walk(ast_tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant) and node.test.value in [False, 0, None]:
            pytest.fail(f"File {file_path.name} contains an unrelated `if False:` block", pytrace=False)


def test_static_analysis(ast_trees: Dict[Path, ast.AST], target_files: List[Path], request: pytest.FixtureRequest) -> None:
    """Run static analysis checks (flake8, mypy, bandit)."""
    max_complexity = request.config.getoption("--max-complexity")
    for file_path in target_files:
        run_flake8(file_path, max_complexity)
        if request.config.getoption("--run-mypy"):
            run_mypy(file_path)
        if request.config.getoption("--run-bandit"):
            run_bandit(file_path)


def test_code_quality(ast_trees: Dict[Path, ast.AST], request: pytest.FixtureRequest) -> None:
    """Run AST-based code quality checks."""
    max_func_lines = request.config.getoption("--max-func-lines")
    strict = request.config.getoption("--strict")
    for file_path, ast_tree in ast_trees.items():
        check_ast_tree(file_path, ast_tree, max_func_lines, strict)
