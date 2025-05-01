# Bad Vibe Scanner

The **Bad Vibe Scanner** is a comprehensive code quality analysis and task management system for Python codebases. It identifies code quality issues ("bad vibes"), aggregates them into tasks, and provides tools to manage the improvement workflow.

## Overview

Bad Vibe Scanner combines static analysis, error parsing, and task management to create a complete quality improvement pipeline:

1. **Scan**: Run static analysis tools to identify code quality issues
2. **Parse**: Convert quality issues into structured task data
3. **Manage**: Import tasks into a database and track their progress

## Features

### Core Functionality
- **Code Quality Check**: Static analysis with 17+ checks and external tools
- **Task Management**: SQLite database-backed task tracking system
- **Markdown Reporting**: Structured reports for code quality issues
- **Workflow Automation**: pipeline with single command exec

### Quality Checks (Built-in)
| Code | Check | Description |
|------|-------|-------------|
| BS001 | function_length | Functions exceeding configured line limit |
| BS002 | assertion_density | Functions with insufficient assertions |
| BS003 | mutable_default | Use of mutable default arguments |
| BS004 | mixed_return | Functions with inconsistent return types |
| BS005 | parameter_validation | Missing early parameter validation |
| BS006 | prohibited_compare | Improper comparison patterns (e.g., `== None`) |
| BS007 | nesting_depth | Excessive nesting depth in functions |
| BS008 | wildcard_import | Use of wildcard imports (`from x import *`) |
| BS009 | exec_eval | Use of `exec()` or `eval()` |
| BS010 | dead_if | Dead code in if-blocks with constant conditions |
| BS011 | unused_local | Unused local variables |
| BS012 | max_args | Functions with too many arguments |
| BS013 | bare_except | Use of bare except clauses |
| BS014 | forbidden_calls | Calls to forbidden functions (print, eval, exec) |
| BS015 | global_nonlocal | Use of global or nonlocal statements |
| BS016 | long_lines | Lines exceeding character limit (default 88) |
| BS017 | mixed_tabs_spaces | Mixed use of tabs and spaces |

### External Tool Integration
| Code | Tool | Description |
|------|------|-------------|
| EXT001 | ruff/flake8 | General linting issues |
| EXT002 | mypy | Type checking issues |
| EXT003 | bandit | Security vulnerabilities |
| EXT004 | black | Code formatting issues |
| EXT005 | isort | Import ordering issues |
| EXT006 | pip-audit | Dependency vulnerabilities |

### Runtime Checks
| Code | Check | Description |
|------|------|-------------|
| RTN001 | unexpected_none | Function returns None contrary to type annotation |
| RTN002 | crash_on_none | Function crashes when called with None arguments |
| RTN003 | missing_docstring | Function missing docstring |

## Installation

### Prerequisites
- Python 3.8+ (3.11 recommended)
- pip (for dependency installation)

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/username/bad-vibe-scanner.git
   cd bad-vibe-scanner
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv adk
   source adk/bin/activate  # On Windows: adk\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Scanner

There are **three ways** to run the Bad Vibe Scanner:

### 1. Automated Workflow (Recommended)

The simplest method is to use the provided `run.sh` script, which automates the entire workflow:

```bash
./run.sh
```

This script:
- Backs up and resets the database
- Runs code quality checks in strict mode
- Parses results into structured tasks
- Imports tasks into the database
- Displays a summary of issues found

### 2. Running as a Python Module

For more control, you can run the scanner directly as a Python module:

```bash
python tests/test_code_quality_gate.py --files src/ --strict --output markdown --output-file bs-test-results-full.md
```

Then parse the results and import them:

```bash
python bs_task_parser.py
python -m task_engine.manage_tasks --import-md bs-test-results-full.md
```

### 3. Running with pytest Integration

You can also run the scanner as a pytest plugin:

```bash
python -m pytest tests/test_code_quality_gate.py --code-quality --files src/ --strict
```

## Configuration Options

### Command Line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--files PATH [PATH ...]` | `.` | Files/directories to analyze |
| `--config PATH` | None | Path to YAML config file |
| `--strict` | False | Enable stricter checks |
| `--max-func-lines N` | 50 | Maximum function length |
| `--max-nesting-depth N` | 3 | Maximum nesting depth |
| `--max-complexity N` | 10 | Maximum cyclomatic complexity |
| `--checks LIST` | "all" | Comma-separated list of checks to run |
| `--use-ruff` | False | Use Ruff instead of Flake8 |
| `--format-check` | False | Run Black and Isort checks |
| `--run-mypy` | False | Run Mypy type checking |
| `--run-bandit` | False | Run Bandit security checks |
| `--run-audit` | False | Run pip-audit for vulnerabilities |
| `--output FORMAT` | "text" | Output format: "text", "json", or "markdown" |
| `--output-file PATH` | None | File to write output to |

### YAML Configuration

You can define settings in `config.yaml`:

```yaml
strict: true
max_func_lines: 30
max_nesting_depth: 2
max_complexity: 8
use_ruff: true
format_check: true
run_mypy: true
run_bandit: true
run_audit: true
output: markdown
output_file: bs-test-results-full.md
checks: all  # or comma-separated list like "function_length,nesting_depth"
```

Then run with:
```bash
python tests/test_code_quality_gate.py --config config.yaml
```

### Strictest Mode Settings

For the highest quality standards:

```bash
python tests/test_code_quality_gate.py \
  --files src/ \
  --strict \
  --max-func-lines 15 \
  --max-nesting-depth 1 \
  --max-complexity 5 \
  --checks all \
  --use-ruff \
  --format-check \
  --run-mypy \
  --run-bandit \
  --run-audit
```

## Task Management

After running the scanner and importing tasks, you can manage them with the following commands:

### Commands

```bash
# Plan a specific task
python -m task_engine.manage_tasks --plan TASK_ID

# Generate a fix for a task
python -m task_engine.manage_tasks --fix TASK_ID

# Verify a fix
python -m task_engine.manage_tasks --verify TASK_ID

# Mark a task as complete
python -m task_engine.manage_tasks --complete TASK_ID

# Process multiple tasks automatically
python -m task_engine.manage_tasks --agent-loop --batch 5
```

### Database Operations

```bash
# View database schema
sqlite3 tasks.db ".schema"

# Count tasks in database
sqlite3 tasks.db "SELECT COUNT(*) FROM tasks"

# View tasks with issues
sqlite3 tasks.db "SELECT id, filename, line, task FROM tasks WHERE status='TODO'"

# Reset the database (careful!)
sqlite3 tasks.db "DELETE FROM tasks; DELETE FROM events; VACUUM;"
```

## Suppressing Issues

Suppress checks using inline comments:

```python
# Suppress a specific check
def long_function():  # noqa: BS001
    pass

# Suppress all checks on a line
x = eval("1 + 1")  # noqa
```

## Extending with Custom Checks

Create custom checks by adding Python modules to a `checks/` directory:

```python
# checks/my_custom_check.py
from tests.test_code_quality_gate import CodeCheck

class CustomCheck(CodeCheck):
    code = "BS099"
    def check(self, node, src, cfg):
        # Your check logic here
        if problem_detected:
            return [(node.lineno, "Description of issue", self.code)]
        return []
```

## Code Quality Reports

The scanner generates reports in multiple formats:

### Text Output (Default)
Shows violations and metrics for each file with line numbers.

### Markdown Output
Structured format suitable for GitHub display and parsing:

```markdown
### src/bad.py
- Line 10: Function exceeds maximum line count (code: BS001)
- Line 15: Security issue: using eval() (code: BS009)
```

### JSON Output
Machine-readable format for integration with other tools:

```json
[
  {
    "file": "src/bad.py",
    "violations": [
      [10, "Function exceeds maximum line count", "BS001"],
      [15, "Security issue: using eval()", "BS009"]
    ],
    "metrics": {
      "funcs": 5,
      "asserts": 2,
      "avg": 0.4,
      "lines": 150
    }
  }
]
```

## Directory Structure

```
bad-vibe-scanner/
├── src/                    # Sample code with intentional issues
├── task_engine/            # Task management system
│   ├── manage_tasks.py     # Core task management functionality
│   ├── config.py           # Configuration utilities
│   ├── mcp_helper.py       # Model Context Protocol integration
│   └── task_schema.sql     # Database schema
├── tests/                  # Test suite for all components
│   ├── test_code_quality_gate.py  # Quality analysis tool
│   ├── test_quality_pipeline.py   # End-to-end pipeline tests
│   └── test_manage_tasks.py       # Task management tests
├── bs_task_parser.py       # Parses quality issues into structured tasks
├── config.yaml             # System configuration
├── run.sh                  # Automated workflow script
├── tasks.db                # SQLite database for task storage
└── README.md               # This documentation
```

## Workflow Integration

### Continuous Integration

Example GitHub Actions workflow:

```yaml
name: Code Quality
on: [push, pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: ./run.sh
      - name: Upload quality report
        uses: actions/upload-artifact@v3
        with:
          name: quality-report
          path: structured_task_list.md
```

### Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: bad-vibe-scanner
      name: Bad Vibe Scanner
      entry: ./run.sh
      language: system
      pass_filenames: false
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Scanner hangs | Run directly with `--max-workers=1` option |
| Database ID conflicts | Clear the database first or let task parser omit IDs |
| Parser fails | Ensure report format matches expectations or use `--output markdown` |
| External tool errors | Verify all tools are installed via requirements.txt |
| Output formatting issues | Try different output formats with `--output [text|json|markdown]` |

## Current Development Status

As of May 2025:
- Complete workflow automation with run.sh
- Fixed task parser ID handling to work with SQLite autoincrement
- Enhanced strictest mode with fine-tuned quality thresholds
- Added categorized task summary by severity
- Improved database backup and reset functionality

## Coming Soon

- Web dashboard for task visualization
- Plugin system for custom quality checks
- IDE extensions for VS Code and JetBrains
- Machine learning model to predict quality issues
- Team collaboration features

## License

MIT License
