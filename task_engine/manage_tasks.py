"""
RooCore V2 CLI.

`python -m task_engine.manage_tasks --help`  for usage.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import mcp_helper, config

DB_PATH = Path("tasks.db")
SCHEMA_SQL = Path(__file__).with_name("task_schema.sql")


# --------------------------------------------------------------------- #
def _ensure_db() -> None:
    if not DB_PATH.exists():
        print("[DB] Initialising tasks.db")
        sql = SCHEMA_SQL.read_text(encoding="utf-8")
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript(sql)


@contextlib.contextmanager
def _db() -> sqlite3.Connection:  # context helper
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()


def _log_event(
    conn: sqlite3.Connection, task_id: int, etype: str, payload: str = ""
) -> None:
    conn.execute(
        "INSERT INTO events (task_id, event_type, payload) VALUES (?,?,?)",
        (task_id, etype, payload),
    )


# --------------------------------------------------------------------- #
def scan(path: str) -> None:
    """Run pytest+ruff+mypy+bandit scan."""
    cmd: list[str] = [
        "pytest",
        "--target",
        path,
        "--ruff",
        "--run-mypy",
        "--run-bandit",
        "--run-audit",
    ]
    subprocess.run(cmd, check=False)


def import_md(md_file: str) -> None:
    """Import markdown task file."""
    import bs_task_parser  # user-supplied module

    df = bs_task_parser.parse_task_file(md_file)
    with _db() as conn:
        df.to_sql("tasks", conn, if_exists="append", index=False)
    print(f"[IMPORT] {len(df)} tasks")


def _update_status(conn: sqlite3.Connection, task_id: int, new_status: str) -> None:
    conn.execute(
        "UPDATE tasks SET status = ?, fixed_at = ? WHERE id = ?",
        (new_status, _dt.datetime.utcnow().isoformat(), task_id),
    )


def plan(task_id: int) -> None:
    with _db() as conn:
        plan_txt = mcp_helper.plan(task_id)
        _log_event(conn, task_id, "PLAN", plan_txt)


def fix(task_id: int) -> None:
    with _db() as conn:
        res = mcp_helper.merge_files(["dummy.py"])
        _log_event(conn, task_id, "FIX", res)


def verify(task_id: int) -> None:
    with _db() as conn:
        res = mcp_helper.security_scan("dummy-code")
        _log_event(conn, task_id, "VERIFY", res)


def complete(task_id: int) -> None:
    with _db() as conn:
        _update_status(conn, task_id, "DONE")
        _log_event(conn, task_id, "COMPLETE", "closed")


def agent_loop(batch: int) -> None:
    with _db() as conn:
        rows = conn.execute(
            "SELECT id FROM tasks WHERE status='TODO' LIMIT ?", (batch,)
        ).fetchall()
    for r in rows:
        tid: int = r["id"]
        plan(tid)
        fix(tid)
        verify(tid)
        complete(tid)
    print(f"[Agent] processed {len(rows)} task(s)")


# --------------------------------------------------------------------- #
def cli() -> None:
    _ensure_db()
    ap = argparse.ArgumentParser(prog="roocore", description="RooCore V2 CLI")
    ap.add_argument("--scan")
    ap.add_argument("--import-md")
    ap.add_argument("--plan", type=int)
    ap.add_argument("--fix", type=int)
    ap.add_argument("--verify", type=int)
    ap.add_argument("--complete", type=int)
    ap.add_argument("--agent-loop", action="store_true")
    ap.add_argument("--batch", type=int, default=5, help="batch size for agent loop")
    ns = ap.parse_args()

    if ns.scan:
        scan(ns.scan)
    elif ns.import_md:
        import_md(ns.import_md)
    elif ns.plan is not None:
        plan(ns.plan)
    elif ns.fix is not None:
        fix(ns.fix)
    elif ns.verify is not None:
        verify(ns.verify)
    elif ns.complete is not None:
        complete(ns.complete)
    elif ns.agent_loop:
        agent_loop(ns.batch)
    else:
        ap.print_help()


if __name__ == "__main__":
    cli()
