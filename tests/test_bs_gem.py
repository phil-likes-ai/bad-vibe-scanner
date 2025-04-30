# test_bs.py
# Automated Code Hygiene Gate based on Pytest

import ast
import collections
import os
import pathlib
import subprocess
import sys
import typing
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Type, Union

import pytest

# --- Try importing optional tools ---

# Attempt to import Flake8 API (though subprocess is simpler here)
try:
    pytest.importorskip("flake8")
    # We'll use subprocess for simplicity and better isolation anyway
except ImportError:
    pass  # Flake8 test will be skipped if command is not found

# Mypy (only used via subprocess)
try:
    pytest.importorskip("mypy")
except ImportError:
    pass  # Mypy test will be skipped if command is not found

# Bandit (only used via subprocess)
try:
    pytest.importorskip("bandit")
except ImportError:
    pass  # Bandit test will be skipped if command is not found


# --- Command Line Options ---


def pytest_addoption(parser: pytest.Parser):
    """Add custom command-line options for the test suite."""
    group = parser.getgroup("code hygiene")
    group.addoption(
        "--script",
        action="store",
        type=pathlib.Path,
        default=None,
        help="Path to the Python script or package directory to analyze (REQUIRED)",
    )
    group.addoption(
        "--strict",
        action="store_true",
        default=False,
        help="Enable stricter checks for some rules",
    )
    group.addoption(
        "--max-func-lines",
        action="store",
        type=int,
        default=50,
        help="Maximum allowed lines per function (default: 50)",
    )
    group.addoption(
        "--run-mypy",
        action="store_true",
        default=False,
        help="Run Mypy static type checker",
    )
    group.addoption(
        "--run-bandit",
        action="store_true",
        default=False,
        help="Run Bandit security linter",
    )
    group.addoption(
        "--max-complexity",
        action="store",
        type=int,
        default=None,  # flake8 default varies, often 10
        help="Maximum cyclomatic complexity (for flake8-mccabe)",
    )


def pytest_configure(config: pytest.Config):
    """Validate command-line options."""
    script_path = config.getoption("--script")
    if not script_path:
        pytest.exit("--script option is required.", returncode=1)
    if not script_path.exists():
        pytest.exit(
            f"Path specified by --script does not exist: {script_path}", returncode=1
        )

    config.addinivalue_line(
        "markers", "ast_check: Mark a test as performing AST-based checks."
    )


# --- Fixtures ---


@pytest.fixture(scope="session")
def target_path(pytestconfig: pytest.Config) -> pathlib.Path:
    """Return the validated target path from the --script option."""
    path = pytestconfig.getoption("--script")
    assert path is not None  # Should be guaranteed by pytest_configure
    return path.resolve()


@pytest.fixture(scope="session")
def is_strict(pytestconfig: pytest.Config) -> bool:
    """Return the value of the --strict flag."""
    return pytestconfig.getoption("--strict")


@pytest.fixture(scope="session")
def max_func_lines(pytestconfig: pytest.Config) -> int:
    """Return the value of the --max-func-lines option."""
    return pytestconfig.getoption("--max-func-lines")


@pytest.fixture(scope="session")
def should_run_mypy(pytestconfig: pytest.Config) -> bool:
    """Return the value of the --run-mypy flag."""
    return pytestconfig.getoption("--run-mypy")


@pytest.fixture(scope="session")
def should_run_bandit(pytestconfig: pytest.Config) -> bool:
    """Return the value of the --run-bandit flag."""
    return pytestconfig.getoption("--run-bandit")


@pytest.fixture(scope="session")
def max_complexity(pytestconfig: pytest.Config) -> Optional[int]:
    """Return the value of the --max-complexity option."""
    return pytestconfig.getoption("--max-complexity")


@pytest.fixture(scope="session")
def python_files(target_path: pathlib.Path) -> List[pathlib.Path]:
    """Collect all Python files (*.py) under the target path."""
    if target_path.is_file():
        if target_path.suffix == ".py":
            return [target_path]
        else:
            pytest.fail(
                f"Target path {target_path} is a file but not a .py file.",
                pytrace=False,
            )
            return []  # Should not be reached
    elif target_path.is_dir():
        return list(target_path.rglob("*.py"))
    else:
        pytest.fail(
            f"Target path {target_path} is not a file or directory.", pytrace=False
        )
        return []  # Should not be reached


ParsedFile = collections.namedtuple("ParsedFile", ["path", "source", "tree"])


@pytest.fixture(scope="session")
def parsed_files(python_files: List[pathlib.Path]) -> List[ParsedFile]:
    """Parse all collected Python files into ASTs, storing source and tree."""
    parsed: List[ParsedFile] = []
    errors = []
    for file_path in python_files:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
            parsed.append(ParsedFile(file_path, source, tree))
        except SyntaxError as e:
            errors.append(f"Failed to parse {file_path}: {e}")
        except Exception as e:
            errors.append(f"Unexpected error parsing {file_path}: {e}")

    if errors:
        pytest.fail(
            "Errors encountered during AST parsing:\n" + "\n".join(errors),
            pytrace=False,
        )

    return parsed


# --- Static Analysis Tests ---


def _run_external_tool(cmd: List[str], tool_name: str) -> None:
    """Helper to run an external tool via subprocess."""
    try:
        # Check if the tool exists using 'where' on Windows, 'command -v' otherwise
        check_cmd = (
            ["where", cmd[0]] if sys.platform == "win32" else ["command", "-v", cmd[0]]
        )
        subprocess.check_output(
            check_cmd, stderr=subprocess.STDOUT, text=True, encoding="utf-8"
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip(f"{tool_name} command not found in PATH.")
        return  # Should not be reached

    try:
        print(f"\nRunning {tool_name}: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # Don't raise exception on non-zero exit code
            encoding="utf-8",
        )
        print(f"{tool_name} stdout:\n{result.stdout}")
        if result.stderr:
            print(f"{tool_name} stderr:\n{result.stderr}")

        if result.returncode != 0:
            pytest.fail(
                f"{tool_name} reported issues (exit code {result.returncode}). See output above.",
                pytrace=False,
            )

    except FileNotFoundError:
        # This case should ideally be caught by the check above, but as a fallback
        pytest.skip(f"{tool_name} command not found in PATH.")
    except Exception as e:
        pytest.fail(f"Error running {tool_name}: {e}", pytrace=False)


def test_flake8(target_path: pathlib.Path, max_complexity: Optional[int]):
    """Run Flake8 static analysis."""
    pytest.importorskip("flake8")  # Check if installed
    cmd = [sys.executable, "-m", "flake8", str(target_path)]
    if max_complexity is not None:
        cmd.append(f"--max-complexity={max_complexity}")
    _run_external_tool(cmd, "Flake8")


def test_mypy(target_path: pathlib.Path, should_run_mypy: bool):
    """Run Mypy static type checker (optional)."""
    if not should_run_mypy:
        pytest.skip("Mypy check skipped: --run-mypy flag not provided.")
    pytest.importorskip("mypy")  # Check if installed
    cmd = [sys.executable, "-m", "mypy", str(target_path)]
    _run_external_tool(cmd, "Mypy")


def test_bandit(target_path: pathlib.Path, should_run_bandit: bool):
    """Run Bandit security linter (optional)."""
    if not should_run_bandit:
        pytest.skip("Bandit check skipped: --run-bandit flag not provided.")
    pytest.importorskip("bandit")  # Check if installed
    # Bandit needs '-r' for recursive directory scan
    cmd = [sys.executable, "-m", "bandit", "-r", str(target_path)]
    _run_external_tool(cmd, "Bandit")


# --- AST Analysis ---


class CodeAnalyzer(ast.NodeVisitor):
    """
    Visits AST nodes to collect metrics and identify problematic patterns.
    """

    def __init__(self, file_path: pathlib.Path, source: str):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.results: Dict[str, List[Tuple[int, str]]] = collections.defaultdict(list)
        self.functions: List[Dict[str, Any]] = []
        self._current_function_data: Optional[Dict[str, Any]] = None

    def _add_result(self, check_name: str, node: ast.AST, message: str):
        lineno = getattr(node, "lineno", 0)
        self.results[check_name].append((lineno, message))

    def _get_node_line_count(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef]
    ) -> int:
        """Calculate the number of logical lines in a node's body."""
        if not node.body:
            return 0

        # Find the end line number, considering decorators
        start_line = node.lineno - 1  # ast lineno is 1-based
        if node.decorator_list:
            start_line = node.decorator_list[0].lineno - 1

        # Find the maximum line number within the node's body recursively
        max_line = 0
        for child in ast.walk(node):
            if hasattr(child, "lineno"):
                max_line = max(max_line, child.lineno)
            # handle nodes that might span multiple lines like strings or expressions
            if hasattr(child, "end_lineno") and child.end_lineno:
                max_line = max(max_line, child.end_lineno)

        # If no nodes with line numbers found in body (e.g., just 'pass'), use node's line
        if max_line == 0:
            max_line = node.lineno

        # Estimate physical lines count. This isn't perfect for logical lines but
        # simpler than full logical line counting without external libraries.
        num_lines = max_line - start_line
        return num_lines if num_lines > 0 else 1

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.visit_FunctionDef_or_AsyncFunctionDef(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef_or_AsyncFunctionDef(node)

    def visit_FunctionDef_or_AsyncFunctionDef(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ):
        # --- Function Analysis ---
        func_name = f"{self.file_path.name}::{node.name}"
        num_lines = self._get_node_line_count(node)
        start_lineno = node.lineno
        params = [arg.arg for arg in node.args.args]
        defaults = node.args.defaults
        # Check for mutable defaults
        for default in defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add_result(
                    "mutable_default_arg",
                    default,
                    f"Function '{func_name}' uses mutable default argument ({ast.dump(default)})",
                )

        # Store function info for later checks
        self._current_function_data = {
            "name": func_name,
            "node": node,
            "lineno": start_lineno,
            "lines": num_lines,
            "params": params,
            "assertion_count": 0,
            "has_value_return": False,
            "has_bare_return": False,
            "has_implicit_return": True,  # Assume implicit until explicit found
            "local_vars": collections.defaultdict(
                lambda: {"assign": 0, "load": 0, "nodes": []}
            ),
            "param_validation_present": False,
            "body_start_lineno": node.body[0].lineno if node.body else node.lineno,
        }

        # --- Local Variable Tracking (Initial Assignment/Load) ---
        # Params are implicitly assigned
        for param in params:
            self._current_function_data["local_vars"][param]["assign"] = 1
            # Find param node for location later if needed
            for arg_node in node.args.args:
                if arg_node.arg == param:
                    self._current_function_data["local_vars"][param]["nodes"].append(
                        arg_node
                    )
                    break

        # --- Traverse Function Body ---
        self.generic_visit(node)  # Visit children

        # --- Post-Traversal Function Checks ---
        if self._current_function_data:
            # Implicit return check update
            if (
                self._current_function_data["has_value_return"]
                or self._current_function_data["has_bare_return"]
            ):
                self._current_function_data["has_implicit_return"] = False

            # Parameter Validation Check Logic
            if params:
                # Does first statement involve a parameter?
                first_nodes = []
                if node.body:
                    first_stmt = node.body[0]
                    # Look for If or Assert as the first statement(s)
                    if isinstance(first_stmt, (ast.If, ast.Assert)):
                        first_nodes.append(first_stmt)
                        # Check consecutive If/Asserts too
                        for stmt in node.body[1:3]:  # Check next couple statements
                            if isinstance(stmt, (ast.If, ast.Assert)):
                                first_nodes.append(stmt)
                            else:
                                break

                    # Check if any parameter name appears in the validation nodes
                    param_validation_found = False
                    for validation_node in first_nodes:
                        for sub_node in ast.walk(validation_node):
                            if isinstance(sub_node, ast.Name) and sub_node.id in params:
                                param_validation_found = True
                                break
                        if param_validation_found:
                            break
                    self._current_function_data["param_validation_present"] = (
                        param_validation_found
                    )

            # --- Unused Local Variable Check ---
            local_vars_info = self._current_function_data["local_vars"]
            for var_name, usage in local_vars_info.items():
                # Simple heuristic: assigned once, never loaded? (and not a parameter)
                if (
                    usage["assign"] > 0
                    and usage["load"] == 0
                    and var_name not in params
                ):
                    # Use the first assignment node for the line number
                    assign_node = usage["nodes"][0] if usage["nodes"] else node
                    self._add_result(
                        "unused_local_variable",
                        assign_node,
                        f"Function '{func_name}': Local variable '{var_name}' assigned but never used.",
                    )

            # Add collected function data
            self.functions.append(self._current_function_data)
            self._current_function_data = None  # Reset for next function

    def visit_Assert(self, node: ast.Assert):
        if self._current_function_data:
            self._current_function_data["assertion_count"] += 1
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if self._current_function_data:
            if node.value:
                self._current_function_data["has_value_return"] = True
            else:
                self._current_function_data["has_bare_return"] = True
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        # Check for `== None`, `!= None`
        if isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            if isinstance(node.left, ast.Constant) and node.left.value is None:
                self._add_result(
                    "comparison_to_none",
                    node,
                    f"Avoid '== None' or '!= None', use 'is None' or 'is not None'. Found: {ast.dump(node)}",
                )
            if (
                len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and node.comparators[0].value is None
            ):
                self._add_result(
                    "comparison_to_none",
                    node,
                    f"Avoid '== None' or '!= None', use 'is None' or 'is not None'. Found: {ast.dump(node)}",
                )

        # Check for `== True/False`, `is True/False`
        if isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
            # Check left operand if it's a simple comparison `X == True`
            if isinstance(node.left, ast.Constant) and isinstance(
                node.left.value, bool
            ):
                self._add_result(
                    "comparison_to_bool",
                    node,
                    f"Avoid explicit comparison to True/False. Found: {ast.dump(node)}",
                )
            # Check right operand(s) `if x == True:`
            for comp in node.comparators:
                if isinstance(comp, ast.Constant) and isinstance(comp.value, bool):
                    self._add_result(
                        "comparison_to_bool",
                        node,
                        f"Avoid explicit comparison to True/False. Found: {ast.dump(node)}",
                    )

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # Check for `if False:`, `if 0:`, `if None:`
        is_problem = False
        if isinstance(node.test, ast.Constant):
            if (
                node.test.value is False
                or node.test.value == 0
                or node.test.value is None
            ):
                is_problem = True
        elif (
            isinstance(node.test, ast.Num) and node.test.n == 0
        ):  # Python 2 compatibility for ast.Num
            is_problem = True

        if is_problem:
            self._add_result(
                "dead_if_block",
                node,
                f"Found 'if {ast.dump(node.test)}:' block, which might indicate dead code.",
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # Check for wildcard imports `from x import *`
        if node.names and node.names[0].name == "*":
            self._add_result(
                "wildcard_import",
                node,
                f"Wildcard import found: 'from {node.module or ''} import *'. Avoid this.",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Check for calls to `exec()` or `eval()`
        if isinstance(node.func, ast.Name):
            if node.func.id == "exec":
                self._add_result(
                    "exec_call",
                    node,
                    "Call to 'exec()' found. Use with extreme caution.",
                )
            elif node.func.id == "eval":
                self._add_result(
                    "eval_call",
                    node,
                    "Call to 'eval()' found. Use with extreme caution.",
                )

        # Track variable loads within the current function scope
        if self._current_function_data and isinstance(node.func, ast.Name):
            func_name = node.func.id
            # Consider function calls as 'loading' the function name
            if func_name in self._current_function_data["local_vars"]:
                self._current_function_data["local_vars"][func_name]["load"] += 1
                self._current_function_data["local_vars"][func_name]["nodes"].append(
                    node.func
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Track local variable assignments
        if self._current_function_data:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self._current_function_data["local_vars"][var_name]["assign"] += 1
                    self._current_function_data["local_vars"][var_name]["nodes"].append(
                        target
                    )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # Track variable loads (reads)
        if self._current_function_data and isinstance(node.ctx, ast.Load):
            var_name = node.id
            if var_name in self._current_function_data["local_vars"]:
                self._current_function_data["local_vars"][var_name]["load"] += 1
                self._current_function_data["local_vars"][var_name]["nodes"].append(
                    node
                )
        self.generic_visit(node)


# --- AST-based Test Functions ---


@pytest.fixture(scope="session")
def analysis_results(parsed_files: List[ParsedFile]) -> List[CodeAnalyzer]:
    """Run CodeAnalyzer on all parsed files."""
    results = []
    for pfile in parsed_files:
        analyzer = CodeAnalyzer(pfile.path, pfile.source)
        analyzer.visit(pfile.tree)
        results.append(analyzer)
    return results


@pytest.mark.ast_check
def test_function_length(analysis_results: List[CodeAnalyzer], max_func_lines: int):
    """Check if any function exceeds the maximum allowed line count."""
    errors = []
    for analyzer in analysis_results:
        for func_data in analyzer.functions:
            if func_data["lines"] > max_func_lines:
                errors.append(
                    f"{func_data['name']} (at line {func_data['lineno']}) "
                    f"has {func_data['lines']} lines (max allowed: {max_func_lines})"
                )
    if errors:
        pytest.fail(
            "Functions exceeding maximum lines:\n" + "\n".join(errors), pytrace=False
        )


@pytest.mark.ast_check
def test_assertion_density(analysis_results: List[CodeAnalyzer], is_strict: bool):
    """Check if functions have a minimum assertion density."""
    errors = []
    min_density = 2.0 if is_strict else 1.0
    for analyzer in analysis_results:
        for func_data in analyzer.functions:
            # Only check functions with some implementation lines
            if func_data["lines"] > 0:
                density = func_data[
                    "assertion_count"
                ]  # Simple count, not per line density
                if density < min_density:
                    errors.append(
                        f"{func_data['name']} (at line {func_data['lineno']}) "
                        f"has {func_data['assertion_count']} assertions "
                        f"(minimum required: {int(min_density)})"
                    )
    if errors:
        pytest.fail(
            f"Functions with low assertion density (min {int(min_density)} assertions per func):\n"
            + "\n".join(errors),
            pytrace=False,
        )


@pytest.mark.ast_check
def test_no_mutable_default_args(analysis_results: List[CodeAnalyzer]):
    """Check for mutable default arguments (list, dict, set)."""
    errors = []
    for analyzer in analysis_results:
        if "mutable_default_arg" in analyzer.results:
            for lineno, message in analyzer.results["mutable_default_arg"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
    if errors:
        pytest.fail(
            "Mutable default arguments found:\n" + "\n".join(errors), pytrace=False
        )


@pytest.mark.ast_check
def test_consistent_return_types(analysis_results: List[CodeAnalyzer]):
    """Check for functions mixing value returns and bare/implicit None returns."""
    errors = []
    for analyzer in analysis_results:
        for func_data in analyzer.functions:
            has_value = func_data["has_value_return"]
            has_none = func_data["has_bare_return"] or func_data["has_implicit_return"]
            if has_value and has_none:
                errors.append(
                    f"{func_data['name']} (at line {func_data['lineno']}) "
                    f"mixes returning values and returning None (explicitly or implicitly)."
                )
    if errors:
        pytest.fail(
            "Functions with mixed return styles found:\n" + "\n".join(errors),
            pytrace=False,
        )


@pytest.mark.ast_check
def test_parameter_validation(analysis_results: List[CodeAnalyzer], is_strict: bool):
    """Check if functions validate their parameters early."""
    errors = []
    min_lines_for_non_strict_check = 3  # Only check funcs > 3 LOC if not strict

    for analyzer in analysis_results:
        for func_data in analyzer.functions:
            # Only check functions with parameters
            if not func_data["params"]:
                continue

            # Determine if check is needed based on strictness and line count
            check_needed = False
            if is_strict:
                check_needed = True
            elif func_data["lines"] > min_lines_for_non_strict_check:
                check_needed = True

            if check_needed and not func_data["param_validation_present"]:
                errors.append(
                    f"{func_data['name']} (at line {func_data['lineno']}) "
                    f"has parameters ({', '.join(func_data['params'])}) but lacks an early "
                    f"'assert' or 'if' statement checking one of them."
                )

    if errors:
        failure_message = "Parameter validation issues found:\n" + "\n".join(errors)
        if not is_strict:
            failure_message += f"\n(Note: Only functions > {min_lines_for_non_strict_check} lines were checked. Use --strict to check all functions.)"
        pytest.fail(failure_message, pytrace=False)


@pytest.mark.ast_check
def test_forbidden_comparisons(analysis_results: List[CodeAnalyzer]):
    """Check for comparisons like '== None', '!= None', '== True', 'is False'."""
    errors = []
    for analyzer in analysis_results:
        if "comparison_to_none" in analyzer.results:
            for lineno, message in analyzer.results["comparison_to_none"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
        if "comparison_to_bool" in analyzer.results:
            for lineno, message in analyzer.results["comparison_to_bool"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
    if errors:
        pytest.fail("Forbidden comparisons found:\n" + "\n".join(errors), pytrace=False)


@pytest.mark.ast_check
def test_no_dead_if_blocks(analysis_results: List[CodeAnalyzer]):
    """Check for 'if False:', 'if 0:', 'if None:' blocks."""
    errors = []
    for analyzer in analysis_results:
        if "dead_if_block" in analyzer.results:
            for lineno, message in analyzer.results["dead_if_block"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
    if errors:
        pytest.fail(
            "Potentially dead 'if' blocks found:\n" + "\n".join(errors), pytrace=False
        )


@pytest.mark.ast_check
def test_no_unused_locals(analysis_results: List[CodeAnalyzer]):
    """Check for unused local variables (simple heuristic)."""
    errors = []
    for analyzer in analysis_results:
        if "unused_local_variable" in analyzer.results:
            for lineno, message in analyzer.results["unused_local_variable"]:
                # Filter out variables starting with '_' as they are often intentionally unused
                var_name = message.split("'")[3]
                if not var_name.startswith("_"):
                    errors.append(f"{analyzer.file_path}:{lineno}: {message}")
    if errors:
        pytest.fail(
            "Potentially unused local variables found (heuristic):\n"
            + "\n".join(errors),
            pytrace=False,
        )


@pytest.mark.ast_check
def test_no_wildcard_imports(analysis_results: List[CodeAnalyzer]):
    """Check for 'from x import *'."""
    errors = []
    for analyzer in analysis_results:
        if "wildcard_import" in analyzer.results:
            for lineno, message in analyzer.results["wildcard_import"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
    if errors:
        pytest.fail("Wildcard imports found:\n" + "\n".join(errors), pytrace=False)


@pytest.mark.ast_check
def test_no_exec_eval(analysis_results: List[CodeAnalyzer]):
    """Check for calls to 'exec()' or 'eval()'."""
    errors = []
    for analyzer in analysis_results:
        if "exec_call" in analyzer.results:
            for lineno, message in analyzer.results["exec_call"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
        if "eval_call" in analyzer.results:
            for lineno, message in analyzer.results["eval_call"]:
                errors.append(f"{analyzer.file_path}:{lineno}: {message}")
    if errors:
        pytest.fail(
            "Calls to 'exec()' or 'eval()' found:\n" + "\n".join(errors), pytrace=False
        )
