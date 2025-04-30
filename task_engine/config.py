"""
Central configuration for RooCore V2.

Edit the MCP_ENDPOINTS and API_TOKEN to match
your actual MCP-server deployment.
"""

from __future__ import annotations

API_TOKEN = "REPLACE_WITH_REAL_TOKEN"

MCP_ENDPOINTS: dict[str, str] = {
    "sequential_thinking": "http://localhost:8001/plan",
    "context_push": "http://localhost:8002/push",
    "context_recall": "http://localhost:8002/recall",
    "file_merger": "http://localhost:8003/merge",
    "ragdocs_lookup": "http://localhost:8004/lookup",
    "ragie_search": "http://localhost:8005/search",
    "secops_scan": "http://localhost:8006/scan",
}

HEADERS = {"Authorization": f"Bearer {API_TOKEN}"}
TIMEOUT_S = 30
MAX_RETRIES = 2
