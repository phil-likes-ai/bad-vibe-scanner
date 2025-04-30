"""
Thin, synchronous HTTP façade over MCP servers.
All network logic lives here – easy to mock in tests.
"""

from __future__ import annotations

import json
import time
from typing import Any, Iterable

import requests

from .config import MCP_ENDPOINTS, HEADERS, TIMEOUT_S, MAX_RETRIES


def _post(endpoint_key: str, payload: dict[str, Any]) -> str:
    url: str = MCP_ENDPOINTS[endpoint_key]
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(
                url, json=payload, headers=HEADERS, timeout=TIMEOUT_S
            )
            response.raise_for_status()
            return response.text
        except Exception as exc:
            if attempt == MAX_RETRIES:
                raise RuntimeError(f"MCP call {endpoint_key} failed: {exc!s}") from exc
            time.sleep(1)  # simple back-off
    assert False, "unreachable"


# ---- exported helpers -------------------------------------------------- #
def plan(task_id: int) -> str:
    return _post("sequential_thinking", {"task_id": task_id})


def push_context(task_id: int, summary: str) -> str:
    return _post("context_push", {"task_id": task_id, "summary": summary})


def recall_context(task_id: int) -> str:
    return _post("context_recall", {"task_id": task_id})


def merge_files(paths: Iterable[str]) -> str:
    return _post("file_merger", {"files": list(paths)})


def docs_lookup(module: str) -> str:
    return _post("ragdocs_lookup", {"module": module})


def docs_search(query: str) -> str:
    return _post("ragie_search", {"query": query})


def security_scan(code: str) -> str:
    return _post("secops_scan", {"code": code})
