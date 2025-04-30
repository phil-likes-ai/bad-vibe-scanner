# BS Scan
## Find the 'Bad Vibes'
Free code quality tests. Scans, tracks, and (soon) fixes your code’s BS if any vibes have been added in error. MIT-licensed: take it, tweak it, break it, enjoy it, just don’t sue me, again, pls! This test suite born out of a day off aims to take away the pains when that there 'vibe coding' gives you er, bad vibes man.

## Quick Start
1. `git clone https://github.com/YOURHANDLE/roocore`
2. `pip install -r requirements.txt`
3. `sqlite3 tasks.db < task_engine/task_schema.sql`
4. `python -m task_engine.manage_tasks --scan ./src`
5. `python -m task_engine.manage_tasks --agent-loop`

## What’s Inside
- **Scanners**: `test_bs_plus.py` (chilled) or `test_bs_plus_plus.py` (strict).
- **Parser**: `parse_bs_tasks.py` turns scan results into tasks.
- **Agent**: Loops fixes via MCP (mock it with `mock_mcp.py`).

## Hack It
- MIT —fork it, break it, make it yours.
- Next steps: Populate skeleton, Add rules, implement parser, replace mock MCP, lots of good fun.

## Notes
- MCP servers are stubs —run `mock_mcp.py` on port 8001.
- Will be replaced shortly. 



## Say hello
- Built by Phil—likes-ai
- X: @PhilLikesAi
- Youtube: https://www.youtube.com/@phil-likes-ai
