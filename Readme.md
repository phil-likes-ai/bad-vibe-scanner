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
# Scan the code
python -m task_engine.manage_tasks scan .

# Import tasks from a markdown file
python -m task_engine.manage_tasks import_md task_list.md

# Plan a task
python -m task_engine.manage_tasks plan TASK_ID

# Fix a specific task
python -m task_engine.manage_tasks fix TASK_ID

# Verify a specific task
python -m task_engine.manage_tasks verify TASK_ID

# Complete a specific task
python -m task_engine.manage_tasks complete TASK_ID

# Process multiple tasks automatically
python -m task_engine.manage_tasks agent_loop --batch 5
```

## Quality Checks

|------|----------------|
| Code Structure | Function length, nesting depth, complexity |
| Testing | Assertion density, test coverage |
| Security | Use of eval/exec, weak crypto |
| Style | Formatting via Black, import order via isort |
| Types | Type annotation issues via mypy |

## All Available Options
| Option | Description |

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

## Creating Custom Checks

You can extend the code analyzer with custom checks by adding your own check classes to a `checks` directory at the root of your project.

### How to Create a Custom Check

1. Create a `checks` directory in your project root:
   ```bash
   mkdir checks
   ```

2. Create a Python file (e.g., `checks/my_custom_check.py`) with your custom check class:
   ```python
   from tests.test_code_quality_gate import CodeCheck
   import ast

   class CustomPatternCheck(CodeCheck):
       code = "CS001"  # Custom code prefix (CS = Custom)
       
       def check(self, node, src, cfg):
           # Example: detect print statements in functions
           if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
               if not any("# noqa" in line for line in [src[node.lineno - 1]]):
                   return [(node.lineno, "Print statement found in production code", self.code)]
           return ()
   ```

3. Your custom check will be automatically loaded and run with the other checks.

### Example Usage with pytest

To run the code quality gate with pytest:

```bash
# Run on all files with custom checks
pytest -xvs tests/test_code_quality_gate.py::test_bs --code-quality

# Run on specific files or directories
pytest -xvs tests/test_code_quality_gate.py::test_bs --code-quality --files src/ tests/

# Run only specific checks
pytest -xvs tests/test_code_quality_gate.py::test_bs --code-quality --checks function_length,assertion_density,CustomPatternCheck
```

### Command Line Usage with Custom Checks

```bash
# Run with custom checks included
python tests/test_code_quality_gate.py --files src/ --output markdown --output-file quality_report.md

# Run only custom checks
python tests/test_code_quality_gate.py --files src/ --checks CustomPatternCheck
```

Custom checks integrate seamlessly with the built-in checks and follow the same suppression pattern:

```python
# Suppress a custom check
def some_function():
    print("Debug info")  # noqa: CS001
