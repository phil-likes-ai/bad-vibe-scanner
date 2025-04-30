# tests/test_manage_tasks.py
import sqlite3
import pytest
from pathlib import Path
from task_engine.manage_tasks import import_md, _ensure_db


@pytest.fixture
def setup_db(tmp_path):
    """Set up a temporary tasks.db."""
    db_path = tmp_path / "tasks.db"
    schema_sql = Path("task_engine/task_schema.sql")
    if schema_sql.exists():
        _ensure_db()
    return db_path


def test_import_md(tmp_path, setup_db):
    """Test importing Markdown tasks to database."""
    md_file = tmp_path / "test.md"
    md_file.write_text("""### src/foo.py\n- Line 10: Fix bug""")
    import_md(str(md_file))
    with sqlite3.connect(str(setup_db)) as conn:
        tasks = conn.execute("SELECT * FROM tasks").fetchall()
        assert len(tasks) == 1
        assert tasks[0]["filename"] == "src/foo.py"
        assert tasks[0]["line"] == 10
        assert tasks[0]["task"] == "Fix bug"
