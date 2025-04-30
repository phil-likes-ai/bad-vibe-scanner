# Bad Vibe Scanner

The **Bad Vibe Scanner** is a Python-based tool for scanning codebases to detect code quality issues ("bad vibes") and managing tasks derived from those issues. It combines static analysis, error parsing, and task management to streamline code improvement workflows. The project is designed to identify violations in Python code, aggregate them into a structured Markdown format, and store them in a database for task tracking.

## Features

- **Static Analysis**: Uses `test_code_quality_gate.py` to detect code quality issues (e.g., missing docstrings, `print` usage, insufficient asserts) with checks.
- **Error Parsing**: `parse_bs_tasks.py` parses test failure reports into a `pandas.DataFrame` and exports them as structured Markdown tables.
- **Task Management**: `task_engine/manage_tasks.py` imports parsed errors into a SQLite database (`tasks.db`) for task tracking.
- **Modern Linters**: Integrates Ruff, Black, Isort, Mypy, Bandit, and pip-audit for comprehensive code quality checks.
- **Extensibility**: Supports pluggable checks via a `checks/` directory and suppression tokens (`# noqa: BSXXX`).
- **CI Integration**: GitHub Actions workflow to automate testing and error reporting.

## Project Structure

```
bad-vibe-scanner/
├── src/
│   └── bad.py              # Example code with intentional issues (e.g., eval)
├── task_engine/
│   ├── manage_tasks.py     # Task management logic (imports tasks to tasks.db)
│   ├── config.py           # Configuration utilities
│   ├── mcp_helper.py       # MCP-related helpers
│   └── task_schema.sql     # SQLite schema for tasks.db
├── tests/
│   ├── test_code_quality_gate.py  # Static analysis and error reporting
│   ├── test_quality_pipeline.py   # Tests the full error-parsing pipeline
│   ├── test_manage_tasks.py       # Tests task_engine integration
│   └── archive/                   # Retired test suites
├── parse_bs_tasks.py       # Parses test failures into Markdown tables
├── config.yaml             # Optional configuration for test suite
├── requirements.txt        # Project dependencies
├── .github/workflows/ci.yml # CI workflow for GitHub Actions
└── README.md               # This file
```

## Installation

### Prerequisites
- **Python**: 3.8 or higher (3.10 recommended).
- **Git**: To clone the repository.
- **pip**: For installing dependencies.

### Clone the Repository
```bash
git clone https://github.com/phil-likes-ai/bad-vibe-scanner.git
cd bad-vibe-scanner
```

### Install Dependencies
Create and install `requirements.txt`:
```bash
cat << EOF > requirements.txt
pytest>=7.0.0
pandas>=1.5.0
ruff>=0.1.0
black>=23.0.0
isort>=5.10.0
mypy>=1.0.0
bandit>=1.7.0
pip-audit>=2.4.0
pyyaml>=6.0.0
EOF

pip install -r requirements.txt
```

## Usage

The Bad Vibe Scanner operates as a pipeline:
1. **Static Analysis**: Run `test_code_quality_gate.py` to detect code quality issues and output them as a Markdown report.
2. **Error Parsing**: Use `parse_bs_tasks.py` to parse the report into a structured Markdown table.
3. **Task Management**: Import parsed tasks into `tasks.db` using `task_engine/manage_tasks.py`.

### Running the Static Analysis
To scan `parse_bs_tasks.py` and generate a Markdown error report:
```bash
pytest tests/test_code_quality_gate.py --files parse_bs_tasks.py --strict --use-ruff --format-check --run-mypy --run-bandit --run-audit --output markdown --output-file bs-test-results-full.md
```

**Options**:
- `--files <path>`: Target file or directory (e.g., `src/`, `parse_bs_tasks.py`).
- `--strict`: Enforce stricter checks (e.g., 2 asserts per function).
- `--use-ruff`: Use Ruff instead of Flake8.
- `--format-check`: Run Black and Isort in check mode.
- `--run-mypy`: Run Mypy type checker.
- `--run-bandit`: Run Bandit security linter.
- `--run-audit`: Run pip-audit for dependency vulnerabilities.
- `--output markdown`: Output errors in Markdown format.
- `--output-file <file>`: Write output to a file (e.g., `bs-test-results-full.md`).
- `--max-func-lines <N>`: Max function length (default: 50).
- `--max-nesting-depth <N>`: Max nesting depth (default: 3).
- `--max-complexity <N>`: Max cyclomatic complexity (default: 10).

**Example Output (`bs-test-results-full.md`)**:
```
### parse_bs_tasks.py
- Line 10: parse_task_file: 0 asserts (min 2) (code: BS002)
- Line 39: export_markdown: 0 asserts (min 2) (code: BS002)
- Line 50: main: 0 asserts (min 2) (code: BS002)
- Line 10: parse_task_file: no early param validation (code: BS005)
- Line 50: Forbidden call print() (code: BS014)
- Line 10: parse_task_file: missing docstring (code: RTN003)
```

### Parsing Errors
Run `parse_bs_tasks.py` to parse the error report and generate a structured Markdown table:
```bash
python parse_bs_tasks.py
```

This reads `bs-test-results-full.md` and outputs `structured_task_list.md`:
```
# Structured Task List

| ID | Filename           | Line | Task                                                  | Status |
|----|--------------------|------|-------------------------------------------------------|--------|
| 1  | parse_bs_tasks.py  | 10   | parse_task_file: 0 asserts (min 2) (code: BS002)      | TODO   |
| 2  | parse_bs_tasks.py  | 39   | export_markdown: 0 asserts (min 2) (code: BS002)      | TODO   |
| 3  | parse_bs_tasks.py  | 50   | main: 0 asserts (min 2) (code: BS002)                | TODO   |
| 4  | parse_bs_tasks.py  | 10   | parse_task_file: no early param validation (code: BS005) | TODO   |
| 5  | parse_bs_tasks.py  | 50   | Forbidden call print() (code: BS014)                  | TODO   |
| 6  | parse_bs_tasks.py  | 10   | parse_task_file: missing docstring (code: RTN003)     | TODO   |
```

### Importing Tasks
Import the parsed tasks into `tasks.db`:
```bash
python -c "from task_engine.manage_tasks import import_md; import_md('bs-test-results-full.md')"
```

This uses `parse_bs_tasks.py` internally to populate the database.

### Testing the Pipeline
Run the integration test to verify the full pipeline:
```bash
pytest tests/test_quality_pipeline.py -v
```

This tests:
1. `test_code_quality_gate.py` generating `bs-test-results-full.md`.
2. `parse_bs_tasks.py` parsing and exporting to `structured_task_list.md`.
3. `task_engine/manage_tasks.py` importing tasks into `tasks.db`.

## Testing

The project includes three main test suites:

1. **`test_code_quality_gate.py`**:
   - **Purpose**: Static analysis and error reporting.
   - **Run**: `pytest tests/test_code_quality_gate.py --files src/ --strict --use-ruff --format-check --output markdown --output-file bs-test-results-full.md`
   - **Checks**: Function length, assertion density, `print`/`eval`, docstrings, nesting, linters (Ruff, Black, Mypy, etc.), and runtime fuzzing (crashes, `None` returns).
   - **Suppression**: Use `# noqa: BSXXX` to suppress specific violations (e.g., `# noqa: BS014` for `print`).

2. **`test_quality_pipeline.py`**:
   - **Purpose**: Tests the end-to-end pipeline (quality gate → parser → task engine).
   - **Run**: `pytest tests/test_quality_pipeline.py -v`
   - **Verifies**: Correct Markdown output, DataFrame parsing, and database import.

3. **`test_manage_tasks.py`**:
   - **Purpose**: Tests `task_engine/manage_tasks.py`’s `import_md` function.
   - **Run**: `pytest tests/test_manage_tasks.py -v`
   - **Verifies**: Tasks are correctly imported into `tasks.db`.

### CI Integration
The project uses GitHub Actions for continuous integration. The workflow runs all tests and generates error reports.

**`.github/workflows/ci.yml`**:
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -r requirements.txt
      - run: pytest tests/test_code_quality_gate.py --files src/ --files parse_bs_tasks.py --strict --use-ruff --format-check --run-audit --output markdown --output-file bs-test-results-full.md
      - run: python parse_bs_tasks.py
      - run: pytest tests/test_quality_pipeline.py -v
      - run: pytest tests/test_manage_tasks.py -v
```

## Configuration

Customize the test suite with a `config.yaml`:
```yaml
strict: true
use_ruff: true
format_check: true
run_mypy: true
run_bandit: true
run_audit: true
max_func_lines: 30
max_nesting_depth: 2
max_complexity: 8
output: markdown
output_file: bs-test-results-full.md
```

Run with:
```bash
pytest tests/test_code_quality_gate.py --config config.yaml
```

## Troubleshooting

- **Missing Dependencies**:
  ```bash
  ModuleNotFoundError: No module named 'ruff'
  ```
  Install: `pip install ruff`.
- **Markdown Parsing Failure**:
  If `parse_bs_tasks.py` fails, verify `bs-test-results-full.md` matches the expected format (`### filename`, `- Line X: message`). Check regex in `parse_task_file`.
- **Database Errors**:
  Ensure `task_engine/task_schema.sql` exists. If not, create it or mock `_ensure_db`.
- **No Violations**:
  If `bs-test-results-full.md` is empty, test with a buggy file (e.g., `src/bad.py` with `eval`).
- **Test Failures**:
  Check failure messages (e.g., `Line 50: Forbidden call print()`). Fix code or suppress with `# noqa: BS014`.

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/xyz`).
3. Commit changes (`git commit -m "Add XYZ feature"`).
4. Push to the branch (`git push origin feature/xyz`).
5. Open a pull request.

### Adding Custom Checks
Extend the test suite by adding checks to `checks/`:
```python
# checks/my_check.py
from test_code_quality_gate import CodeCheck

class MyCustomCheck(CodeCheck):
    code = "BS018"
    def check(self, node, src, cfg):
        if isinstance(node, ast.Call) and node.func.id == "my_bad_function":
            return [(node.lineno, "Bad function call", self.code)]
        return []
```

The check will be automatically loaded when running `test_code_quality_gate.py`.

## License

MIT License. 

