# Bad Vibe Scanner

A Python code quality analyzer that finds issues in your code and helps you fix them.

## What It Does

- Runs 20+ quality checks on your Python code
- Converts issues into actionable tasks in a database
- Helps you fix problems one by one or in batches

## Quick Start

```bash
# Run the complete workflow
chmod +x run.sh
./run.sh
```

## Key Features

- **Strict Quality Checks**: Identifies function length, nesting depth, complexity issues
- **Security Scanning**: Detects eval/exec usage and other vulnerabilities
- **External Tool Integration**: Works with ruff, mypy, bandit, black, and isort
- **Task Management**: Tracks issues in SQLite database with full lifecycle support

## How to Use

### Run the Complete Scan

```bash
./run.sh
```

### Manage Tasks

```bash
# List all tasks
python -m task_engine.manage_tasks --list

# Get details for a task
python -m task_engine.manage_tasks --details TASK_ID

# Fix a specific task
python -m task_engine.manage_tasks --fix TASK_ID

# Process multiple tasks automatically
python -m task_engine.manage_tasks --agent-loop --batch 5
```

## Quality Checks

| Type | What It Checks |
|------|----------------|
| Code Structure | Function length, nesting depth, complexity |
| Testing | Assertion density, test coverage |
| Security | Use of eval/exec, weak crypto |
| Style | Formatting via Black, import order via isort |
| Types | Type annotation issues via mypy |

## All Available Options

| Option | Description | Default |
|--------|-------------|---------|
| `--files` | Files or directories to analyze | `["."]` |
| `--config` | Path to YAML config file | `None` |
| `--strict` | Enable strict mode for all checks | `False` |
| `--max-func-lines` | Maximum allowed lines per function | `50` |
| `--max-nesting-depth` | Maximum nesting depth | `3` |
| `--max-complexity` | Maximum cyclomatic complexity | `10` |
| `--run-mypy` | Enable mypy type checking | `False` |
| `--run-bandit` | Enable Bandit security checks | `False` |
| `--run-audit` | Enable pip-audit for dependencies | `False` |
| `--use-ruff` | Use Ruff instead of Flake8 | `False` |
| `--format-check` | Run Black and isort checks | `False` |
| `--checks` | Comma-separated list of checks to run | `"all"` |
| `--output` | Output format (text, json, markdown) | `"text"` |
| `--output-file` | File to write output | `None` |

## Built-in Checks

| Code  | Check | Description |
|-------|-------|-------------|
| BS001 | function_length | Function exceeds line limit |
| BS002 | assertion_density | Insufficient assertions |
| BS003 | mutable_default | Mutable default argument |
| BS004 | mixed_return | Function has mixed return types |
| BS005 | parameter_validation | Missing parameter validation |
| BS006 | prohibited_compare | Improper comparisons |
| BS007 | nesting_depth | Excessive nesting depth |
| BS008 | wildcard_import | Use of wildcard imports |
| BS009 | exec_eval | Use of exec/eval |
| BS010 | dead_if | Dead code in conditionals |
| BS011 | unused_local | Unused local variables |
| BS012 | max_args | Too many function arguments |
| BS013 | bare_except | Bare except clauses |
| BS014 | forbidden_calls | Forbidden function calls |
| BS015 | global_nonlocal | Global/nonlocal usage |
| BS016 | long_lines | Lines > 88 characters |
| BS017 | mixed_tabs_spaces | Mixed tabs and spaces |
| RTN001-003 | runtime | Runtime checks (return values, docstrings) |

## Requirements

- Python 3.8+ (3.11 recommended)
- SQLite 3
- External tools: ruff, mypy, bandit, black, isort, pip-audit

## Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Create a `config.yaml` file or use command-line options with `test_code_quality_gate.py`:

```bash
python tests/test_code_quality_gate.py \
  --files src/ \
  --strict \
  --max-func-lines 15 \
  --max-nesting-depth 1 \
  --max-complexity 5
```

## Suppressing Issues

You can suppress specific issues in your code with comments:

```python
# Suppress a specific issue
def long_function():  # noqa: BS001
    pass

# Suppress all checks on a line
x = eval("1 + 1")  # noqa
```

## License

[MIT License](license.md)
