# test_bs2.py
# Pytest-based Code Hygiene Gate Bad Vibes Suite


from __future__ import annotations

import ast
import collections
import pathlib
import shlex
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

import pytest

# --- Try importing optional tools (for skipping tests if package missing) ---

# These check if the *package* is installed. We'll also check for the
# command-line tool's presence in PATH later before running subprocess.
try:
    pytest.importorskip("flake8")
except ImportError:
    pass
try:
    pytest.importorskip("mypy")
except ImportError:
    pass
try:
    pytest.importorskip("bandit")
except ImportError:
    pass


# --- Command Line Options ---


def pytest_addoption(parser: pytest.Parser):
    """Add custom command-line options for the test suite."""
    group = parser.getgroup("Code Hygiene Gate")
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
        help="Enable stricter checks for assertion density and param validation",
    )
    group.addoption(
        "--max-func-lines",
        action="store",
        type=int,
        default=50,
        help="Maximum allowed lines per function/method (default: 50)",
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
        default=None,
        help="Maximum cyclomatic complexity (for flake8-mccabe, e.g., 10)",
    )


def pytest_configure(config: pytest.Config):
    """Validate command-line options."""
    script_path = config.getoption("--script")
    if not script_path:
        pytest.exit("--script option is required.", returncode=1)
    # Further path validation happens in the target_path fixture

    config.addinivalue_line(
        "markers", "bs_check: Mark a test as related to this hygiene suite."
    )


# --- Fixtures ---


@pytest.fixture(scope="session")
def target_path(pytestconfig: pytest.Config) -> pathlib.Path:
    """Return the validated target path from the --script option."""
    path_opt = pytestconfig.getoption("--script")
    if not path_opt:
        # Should have been caught by pytest_configure, but defense in depth
        pytest.fail("--script option is missing.", pytrace=False)
        raise RuntimeError("Should not reach here")  # for type checker

    path = path_opt.resolve()
    if not path.exists():
        pytest.fail(f"Path specified by --script does not exist: {path}", pytrace=False)
    return path


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
    """Collect all Python files (*.py) under the target path (session scope)."""
    files: List[pathlib.Path] = []
    if target_path.is_file():
        if target_path.suffix == ".py":
            files = [target_path]
        else:
            pytest.fail(
                f"Target path {target_path} is a file but not a .py file.",
                pytrace=False,
            )
    elif target_path.is_dir():
        files = sorted(list(target_path.rglob("*.py")))
    else:
        pytest.fail(
            f"Target path {target_path} is not a valid file or directory.",
            pytrace=False,
        )

    if not files:
        pytest.fail(
            f"No Python files found under target path: {target_path}", pytrace=False
        )

    return files


# Structure to hold parsed file data
ParsedFileData = collections.namedtuple("ParsedFileData", ["path", "source", "tree"])


@pytest.fixture(scope="session")
def parsed_files_data(
    python_files: List[pathlib.Path],
) -> Dict[pathlib.Path, ParsedFileData]:
    """
    Parse all collected Python files into ASTs (session scope).
    Returns a dictionary mapping Path to ParsedFileData.
    """
    parsed: Dict[pathlib.Path, ParsedFileData] = {}
    errors = []
    for file_path in python_files:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
            parsed[file_path] = ParsedFileData(file_path, source, tree)
        except SyntaxError as e:
            errors.append(f"Syntax error parsing {file_path}:{e.lineno}: {e.msg}")
        except Exception as e:
            errors.append(f"Unexpected error parsing {file_path}: {e}")

    if errors:
        pytest.fail(
            "Errors encountered during AST parsing:\n" + "\n".join(errors),
            pytrace=False,
        )

    return parsed


# --- Static Analysis Tests ---


def _find_executable(name: str) -> Optional[str]:
    """Check if an executable exists in the system's PATH."""
    return shutil.which(name)


def _run_external_tool(cmd: List[str], tool_name: str, target_desc: str) -> None:
    """Helper to run an external tool via subprocess and fail test on issues."""
    executable = _find_executable(cmd[0])
    if not executable:
        pytest.skip(f"{tool_name} command ('{cmd[0]}') not found in PATH.")
        return  # Should not be reached

    print(f"\n[{tool_name}] Running: {' '.join(shlex.quote(c) for c in cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,  # We check returncode manually
            encoding="utf-8",
        )

        # Print output for debugging, especially on failure
        if result.stdout:
            print(f"[{tool_name}] stdout:\n{result.stdout.strip()}")
        if result.stderr:
            print(f"[{tool_name}] stderr:\n{result.stderr.strip()}")

        if result.returncode != 0:
            pytest.fail(
                f"{tool_name} found issues in {target_desc} (exit code {result.returncode}).\n"
                f"See output above for details.",
                pytrace=False,
            )
        else:
            print(f"[{tool_name}] OK")

    except Exception as e:
        pytest.fail(f"Error running {tool_name}: {e}", pytrace=False)


@pytest.mark.bs_check
def test_flake8(target_path: pathlib.Path, max_complexity: Optional[int]):
    """Run Flake8 static analysis."""
    # pytest.importorskip("flake8") # Already done globally
    cmd = [sys.executable, "-m", "flake8", str(target_path)]
    if max_complexity is not None:
        cmd.append(f"--max-complexity={max_complexity}")
    _run_external_tool(cmd, "Flake8", f"target '{target_path}'")


@pytest.mark.bs_check
def test_mypy(target_path: pathlib.Path, should_run_mypy: bool):
    """Run Mypy static type checker (optional)."""
    if not should_run_mypy:
        pytest.skip("Mypy check skipped: --run-mypy flag not provided.")
    # pytest.importorskip("mypy") # Already done globally
    # Basic mypy command; might need customization for specific projects
    cmd = [sys.executable, "-m", "mypy", "--ignore-missing-imports", str(target_path)]
    _run_external_tool(cmd, "Mypy", f"target '{target_path}'")


@pytest.mark.bs_check
def test_bandit(target_path: pathlib.Path, should_run_bandit: bool):
    """Run Bandit security linter (optional)."""
    if not should_run_bandit:
        pytest.skip("Bandit check skipped: --run-bandit flag not provided.")
    # pytest.importorskip("bandit") # Already done globally
    cmd = [sys.executable, "-m", "bandit", "-r", str(target_path)]
    _run_external_tool(cmd, "Bandit", f"target '{target_path}'")


# --- AST Analysis Logic ---

# Violation tuple structure: (line_number, message_string)
Violation = Tuple[int, str]

# Structure to hold analysis results for a single file
FileAnalysisResult = collections.namedtuple(
    "FileAnalysisResult",
    [
        "path",
        "violations",  # Dict[str (check_name), List[Violation]]
        "function_details",  # List[Dict[str, Any]] - potentially useful for complex checks
    ],
)


class CodeAnalyzer(ast.NodeVisitor):
    """
    Visits AST nodes to collect metrics and identify problematic patterns.
    Designed to be run once per file.
    """

    # Check names used as keys in the results dictionary
    CHECK_FUNC_LENGTH = "function_length"
    CHECK_ASSERT_DENSITY = "assertion_density"
    CHECK_MUTABLE_DEFAULT = "mutable_default"
    CHECK_MIXED_RETURN = "mixed_return"
    CHECK_PARAM_VALIDATION = "parameter_validation"
    CHECK_FORBIDDEN_COMPARE = "forbidden_compare"
    CHECK_DEAD_IF = "dead_if"
    CHECK_UNUSED_LOCAL = "unused_local"
    CHECK_WILDCARD_IMPORT = "wildcard_import"
    CHECK_EXEC_EVAL = "exec_eval"

    def __init__(self, file_path: pathlib.Path, source: str, cfg: Dict[str, Any]):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.config = cfg  # Holds options like is_strict, max_func_lines

        # Results storage
        self.violations: Dict[str, List[Violation]] = collections.defaultdict(list)
        self.function_details: List[Dict[str, Any]] = []

        # State during traversal
        self._current_function_data: Optional[Dict[str, Any]] = None

    def _add_violation(self, check_name: str, node: ast.AST, message: str):
        """Adds a violation to the results."""
        # AST line numbers are 1-based
        lineno = getattr(node, "lineno", 0)
        if lineno > 0:
            self.violations[check_name].append((lineno, message))
        else:
            # Fallback for nodes without line numbers (should be rare for violations)
            self.violations[check_name].append((0, f"(Line unknown) {message}"))

    def _get_node_line_count(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> int:
        """Calculate the number of physical lines spanning the node."""
        # Note: This calculates physical lines, not logical lines of code.
        # A more precise logical line count would require more complex analysis.
        if not node.body:
            return 0

        start_line = node.lineno
        end_line = getattr(node, "end_lineno", None)

        # Basic fallback for Python < 3.8 or if end_lineno is missing
        if end_line is None:
            max_line = start_line
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    max_line = max(max_line, child.lineno)
            end_line = max_line

        # Ensure end_line is at least start_line
        end_line = max(start_line, end_line)

        return end_line - start_line + 1

    # --- Visitor Methods ---

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._process_function_node(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._process_function_node(node)

    def _process_function_node(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ):
        """Common logic for FunctionDef and AsyncFunctionDef."""
        func_name = f"{self.file_path.name}::{node.name}"
        num_lines = self._get_node_line_count(node)
        start_lineno = node.lineno
        params = [arg.arg for arg in node.args.args]

        # --- Check: Function Length ---
        max_lines = self.config.get("max_func_lines", 50)
        if num_lines > max_lines:
            self._add_violation(
                self.CHECK_FUNC_LENGTH,
                node,
                f"Function '{node.name}' is {num_lines} lines long (max allowed: {max_lines}).",
            )

        # --- Check: Mutable Default Arguments ---
        for default in node.args.defaults or []:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add_violation(
                    self.CHECK_MUTABLE_DEFAULT,
                    default,  # Report on the default node itself
                    f"Function '{node.name}' uses a mutable default argument (list, dict, or set).",
                )
        for default in node.args.kw_defaults or []:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self._add_violation(
                    self.CHECK_MUTABLE_DEFAULT,
                    default,
                    f"Function '{node.name}' uses a mutable default keyword argument (list, dict, or set).",
                )

        # --- Prepare for body analysis ---
        # Store function info for checks that need function scope context
        self._current_function_data = {
            "name": func_name,
            "node": node,
            "lineno": start_lineno,
            "lines": num_lines,
            "params": params,
            "assertion_count": 0,
            "has_value_return": False,
            "has_bare_return": False,
            "has_implicit_return": True,  # Assume implicit until explicit return found
            "local_vars": collections.defaultdict(
                lambda: {"assign_lines": [], "load_lines": []}
            ),
            "param_validation_found": (
                False if params else True
            ),  # Assume valid if no params
        }
        # Parameters are considered assigned at the function definition line
        for param in params:
            self._current_function_data["local_vars"][param]["assign_lines"].append(
                start_lineno
            )

        # --- Traverse Function Body ---
        self.generic_visit(node)  # Visit children BEFORE finalizing function checks

        # --- Finalize Function-Scoped Checks ---
        if self._current_function_data:
            # Update implicit return status
            if (
                self._current_function_data["has_value_return"]
                or self._current_function_data["has_bare_return"]
            ):
                self._current_function_data["has_implicit_return"] = False

            # --- Check: Mixed Return Types ---
            has_value = self._current_function_data["has_value_return"]
            has_none = (
                self._current_function_data["has_bare_return"]
                or self._current_function_data["has_implicit_return"]
            )
            if has_value and has_none:
                self._add_violation(
                    self.CHECK_MIXED_RETURN,
                    node,
                    f"Function '{node.name}' mixes returning values and returning None (explicitly or implicitly).",
                )

            # --- Check: Assertion Density ---
            # Checks for minimum *count* per function, not line density
            min_asserts = 2 if self.config.get("is_strict", False) else 1
            actual_asserts = self._current_function_data["assertion_count"]
            if actual_asserts < min_asserts:
                self._add_violation(
                    self.CHECK_ASSERT_DENSITY,
                    node,
                    f"Function '{node.name}' has only {actual_asserts} assert(s) (minimum required: {min_asserts}).",
                )

            # --- Check: Parameter Validation ---
            if params and not self._current_function_data["param_validation_found"]:
                # When is the check enforced?
                is_strict_mode = self.config.get("is_strict", False)
                enforce_check = is_strict_mode or (num_lines > 3)

                if enforce_check:
                    self._add_violation(
                        self.CHECK_PARAM_VALIDATION,
                        node,
                        f"Function '{node.name}' lacks early parameter validation "
                        f"(an 'if' or 'assert' checking a parameter: {', '.join(params)}).",
                    )

            # --- Check: Unused Local Variables ---
            local_vars_info = self._current_function_data["local_vars"]
            for var_name, usage in local_vars_info.items():
                is_assigned = bool(usage["assign_lines"])
                is_loaded = bool(usage["load_lines"])
                is_parameter = var_name in params
                # Heuristic: assigned, never loaded, not a parameter, not underscore-prefixed
                if (
                    is_assigned
                    and not is_loaded
                    and not is_parameter
                    and not var_name.startswith("_")
                ):
                    # Report violation at the first assignment line
                    first_assign_line = min(usage["assign_lines"])
                    # Need a dummy node with the line number for _add_violation
                    dummy_node = type("DummyNode", (), {"lineno": first_assign_line})()
                    self._add_violation(
                        self.CHECK_UNUSED_LOCAL,
                        dummy_node,
                        f"Local variable '{var_name}' in function '{node.name}' is assigned but never used.",
                    )

            # Store details for potential later use (optional)
            self.function_details.append(self._current_function_data)
            self._current_function_data = None  # Reset for next function

    def visit_Assert(self, node: ast.Assert):
        if self._current_function_data:
            self._current_function_data["assertion_count"] += 1
            # Check if this assert validates a parameter
            if not self._current_function_data["param_validation_found"]:
                params = self._current_function_data["params"]
                for sub_node in ast.walk(node.test):
                    if isinstance(sub_node, ast.Name) and sub_node.id in params:
                        self._current_function_data["param_validation_found"] = True
                        break
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        # --- Check: Parameter validation in 'if' ---
        if (
            self._current_function_data
            and not self._current_function_data["param_validation_found"]
        ):
            # Heuristic: Only check 'if' statements very early in the function body
            func_node = self._current_function_data["node"]
            is_early_statement = False
            if func_node.body and node == func_node.body[0]:
                is_early_statement = True
            # Could extend to check first few statements if needed

            if is_early_statement:
                params = self._current_function_data["params"]
                for sub_node in ast.walk(node.test):
                    if isinstance(sub_node, ast.Name) and sub_node.id in params:
                        self._current_function_data["param_validation_found"] = True
                        break

        # --- Check: Dead 'if' blocks ---
        is_dead_if = False
        if isinstance(node.test, ast.Constant):
            # Note: Python optimizes `if 0:` etc. to `if False:` in AST
            if node.test.value is False or node.test.value is None:
                is_dead_if = True
        # Check `if 0:` for older Python versions
        elif (hasattr(ast, 'Num') and isinstance(node.test, ast.Num) and node.test.n == 0) or \
             (isinstance(node.test, ast.Constant) and node.test.value == 0):
            is_dead_if = True

        if is_dead_if:
            self._add_violation(
                self.CHECK_DEAD_IF,
                node.test,
                f"Found 'if {ast.dump(node.test)}:' block; condition is statically false/None.",
            )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if self._current_function_data:
            if node.value:
                self._current_function_data["has_value_return"] = True
            else:
                self._current_function_data["has_bare_return"] = True
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare):
        # --- Check: Forbidden Comparisons ---
        # Check for `== None` or `!= None`
        if isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            # Check `None == ...` or `... == None`
            operands = [node.left] + node.comparators
            if any(
                isinstance(op, ast.Constant) and op.value is None for op in operands
            ):
                self._add_violation(
                    self.CHECK_FORBIDDEN_COMPARE,
                    node,
                    "Comparison to None using '==' or '!='; use 'is' or 'is not'.",
                )

        # Check for `== True/False` or `is True/False`
        if isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
            operands = [node.left] + node.comparators
            if any(
                isinstance(op, ast.Constant) and isinstance(op.value, bool)
                for op in operands
            ):
                self._add_violation(
                    self.CHECK_FORBIDDEN_COMPARE,
                    node,
                    "Explicit comparison to True/False; use the value directly or 'is'/'is not'.",
                )

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # --- Check: Wildcard Imports ---
        if node.names and any(alias.name == "*" for alias in node.names):
            module_name = node.module or "?"
            self._add_violation(
                self.CHECK_WILDCARD_IMPORT,
                node,
                f"Wildcard import detected: 'from {module_name} import *'. Avoid this.",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # --- Check: exec() and eval() calls ---
        if isinstance(node.func, ast.Name):
            if node.func.id == "exec":
                self._add_violation(
                    self.CHECK_EXEC_EVAL,
                    node,
                    "Call to potentially dangerous function 'exec'.",
                )
            elif node.func.id == "eval":
                self._add_violation(
                    self.CHECK_EXEC_EVAL,
                    node,
                    "Call to potentially dangerous function 'eval'.",
                )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # Track variable usage within the current function
        if self._current_function_data and isinstance(node.ctx, ast.Load):
            var_name = node.id
            if var_name in self._current_function_data["local_vars"]:
                self._current_function_data["local_vars"][var_name][
                    "load_lines"
                ].append(node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Track variable assignments within the current function
        if self._current_function_data:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self._current_function_data["local_vars"][var_name][
                        "assign_lines"
                    ].append(node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        # Track augmented assignments (treat as both load and store)
        if self._current_function_data:
            if isinstance(node.target, ast.Name):
                var_name = node.target.id
                if var_name in self._current_function_data["local_vars"]:
                    self._current_function_data["local_vars"][var_name][
                        "load_lines"
                    ].append(node.lineno)
                self._current_function_data["local_vars"][var_name][
                    "assign_lines"
                ].append(node.lineno)
        self.generic_visit(node)

    def run(self) -> FileAnalysisResult:
        """Runs the visitor on the stored tree and returns results."""
        # Use the already parsed tree from the constructor
        tree = ast.parse("\n".join(self.source_lines))
        self.visit(tree)
        return FileAnalysisResult(
            path=self.file_path,
            violations=dict(self.violations),  # Convert defaultdict back to dict
            function_details=self.function_details,
        )


# --- Fixture to Run Analysis (Session Scoped) ---


@pytest.fixture(scope="session")
def analysis_results(
    parsed_files_data: Dict[pathlib.Path, ParsedFileData],
    is_strict: bool,
    max_func_lines: int,
) -> Dict[pathlib.Path, FileAnalysisResult]:
    """
    Runs the CodeAnalyzer on all parsed files once per session.
    Returns a dictionary mapping Path to FileAnalysisResult.
    """
    results: Dict[pathlib.Path, FileAnalysisResult] = {}
    analyzer_config = {
        "is_strict": is_strict,
        "max_func_lines": max_func_lines,
    }
    print(f"\nAnalyzing {len(parsed_files_data)} files...")
    for file_path, file_data in parsed_files_data.items():
        analyzer = CodeAnalyzer(file_path, file_data.source, analyzer_config)
        results[file_path] = analyzer.run()
        # Simple progress indicator
        print(".", end="", flush=True)
    print(" Analysis complete.")
    return results


# --- AST-based Test Functions (Parametrized) ---


# Helper to format violation messages for test output
def _format_violations(violations: List[Violation]) -> str:
    if not violations:
        return "No violations found."
    # Sort by line number
    sorted_violations = sorted(violations, key=lambda v: v[0])
    return "\n".join([f"  L{line}: {msg}" for line, msg in sorted_violations])


# Create fixtures for parametrize IDs to make test names cleaner
@pytest.fixture
def target_file_path(analysis_results) -> pathlib.Path:
    # Get the keys from the analysis_results dictionary
    paths = list(analysis_results.keys())
    # Use the first path for simplicity
    if paths:
        return paths[0]
    pytest.skip("No files were analyzed")


# Test function for Function Length
@pytest.mark.bs_check
def test_ast_function_length(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Function length violations."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_FUNC_LENGTH, [])
    assert (
        not violations
    ), f"Function length violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Assertion Density
@pytest.mark.bs_check
def test_ast_assertion_density(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Assertion density violations."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_ASSERT_DENSITY, [])
    assert (
        not violations
    ), f"Assertion density violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Mutable Default Arguments
@pytest.mark.bs_check
def test_ast_mutable_default_args(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Mutable default argument violations."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_MUTABLE_DEFAULT, [])
    assert (
        not violations
    ), f"Mutable default argument violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Mixed Return Types
@pytest.mark.bs_check
def test_ast_mixed_return_types(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Mixed value/None return violations."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_MIXED_RETURN, [])
    assert (
        not violations
    ), f"Mixed return type violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Parameter Validation
@pytest.mark.bs_check
def test_ast_parameter_validation(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Missing early parameter validation."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_PARAM_VALIDATION, [])
    assert (
        not violations
    ), f"Missing parameter validation violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Forbidden Comparisons
@pytest.mark.bs_check
def test_ast_forbidden_comparisons(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Forbidden comparisons (e.g., '== None', '== True')."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_FORBIDDEN_COMPARE, [])
    assert (
        not violations
    ), f"Forbidden comparison violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Dead If Blocks
@pytest.mark.bs_check
def test_ast_dead_if_blocks(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Dead 'if' blocks (e.g., 'if False:')."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_DEAD_IF, [])
    assert (
        not violations
    ), f"Dead 'if' block violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Unused Local Variables
@pytest.mark.bs_check
def test_ast_unused_locals(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Unused local variable violations (heuristic)."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_UNUSED_LOCAL, [])
    assert (
        not violations
    ), f"Unused local variable violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for Wildcard Imports
@pytest.mark.bs_check
def test_ast_wildcard_imports(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Wildcard import ('from x import *') violations."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_WILDCARD_IMPORT, [])
    assert (
        not violations
    ), f"Wildcard import violations found in {result.path.name}:\n{_format_violations(violations)}"


# Test function for exec()/eval() Calls
@pytest.mark.bs_check
def test_ast_exec_eval_calls(
    target_file_path: pathlib.Path,
    analysis_results: Dict[pathlib.Path, FileAnalysisResult],
):
    """Check AST: Calls to 'exec()' or 'eval()'."""
    result = analysis_results[target_file_path]
    violations = result.violations.get(CodeAnalyzer.CHECK_EXEC_EVAL, [])
    assert (
        not violations
    ), f"Calls to 'exec()' or 'eval()' found in {result.path.name}:\n{_format_violations(violations)}"
