# tests/test_quality_pipeline.py
import pytest
import tempfile
import os
import pandas as pd
import sqlite3
from pathlib import Path
from tests.test_code_quality_gate import run_quality, report, Config
from bs_task_parser import parse_task_file, export_markdown
from task_engine.manage_tasks import import_md, _ensure_db


@pytest.fixture
def temp_files(tmp_path):
    """Create temporary files for test output."""
    quality_md = tmp_path / "test_results.md"
    structured_md = tmp_path / "task_list.md"
    db_file = tmp_path / "tasks.db"
    return quality_md, structured_md, db_file


@pytest.fixture
def setup_db(tmp_path):
    """Set up a temporary tasks.db."""
    db_path = tmp_path / "tasks.db"
    schema_sql = Path("task_engine/task_schema.sql")
    if schema_sql.exists():
        _ensure_db()
    return db_path


def test_quality_pipeline(temp_files, setup_db):
    """Test the full pipeline: quality gate -> parser -> task engine."""
    quality_md, structured_md, db_file = temp_files

    # Step 1: Run test_code_quality_gate.py to generate error report
    cfg = Config()
    cfg.files = ["parse_bs_tasks.py"]
    cfg.strict = True
    cfg.output = "markdown"
    results = run_quality(cfg)
    report(results, "markdown", str(quality_md))

    # Verify quality_md content
    with open(quality_md, "r", encoding="utf-8") as f:
        content = f.read()
    assert "### parse_bs_tasks.py" in content
    assert "- Line 10: parse_task_file: 0 asserts (min 2) (code: BS002)" in content
    assert "- Line 50: Forbidden call print() (code: BS014)" in content

    # Step 2: Run parse_bs_tasks.py to parse and export
    df = parse_task_file(str(quality_md))
    export_markdown(df, str(structured_md))

    # Verify DataFrame
    assert len(df) >= 3  # At least asserts, param validation, print violations
    assert df.iloc[0].to_dict() == {
        "id": 1,
        "filename": "parse_bs_tasks.py",
        "line": 10,
        "task": "parse_task_file: 0 asserts (min 2) (code: BS002)",
        "status": "TODO",
        "tag": None,
        "severity": None,
        "metadata_json": None,
    }

    # Verify structured_md content
    with open(structured_md, "r", encoding="utf-8") as f:
        content = f.read()
    assert (
        "| 1 | parse_bs_tasks.py | 10 | parse_task_file: 0 asserts (min 2) (code: BS002) | TODO |"
        in content
    )

    # Step 3: Run task_engine/manage_tasks.py to import to database
    import_md(str(quality_md))
    with sqlite3.connect(str(setup_db)) as conn:
        tasks = conn.execute("SELECT * FROM tasks").fetchall()
        assert len(tasks) >= 3
        assert tasks[0]["filename"] == "bs_task_parser.py"
        assert tasks[0]["line"] == 10
        assert "parse_task_file: 0 asserts" in tasks[0]["task"]
