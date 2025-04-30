# Autonomous Task Manager

scans codebases, stores issues as tasks, then plans, fixes, verifies
and closes them by calling live MCP servers.  Live mcp in dev

## Quick start

```bash
sqlite3 tasks.db < task_engine/task_schema.sql
python -m task_engine.manage_tasks --scan ./src
python -m task_engine.manage_tasks --agent-loop
