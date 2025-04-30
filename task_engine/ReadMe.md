# RooCore V2 – Autonomous Task Manager

RooCore V2 scans codebases, stores issues as tasks, then plans, fixes, verifies
and closes them by calling live MCP servers.

## Quick start

```bash
git clone https://github.com/YOURNAME/roocore
cd roocore
pip install -r requirements.txt
sqlite3 tasks.db < task_engine/task_schema.sql
python -m task_engine.manage_tasks --scan ./src
python -m task_engine.manage_tasks --agent-loop
