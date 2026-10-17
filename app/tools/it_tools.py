"""Read-only diagnostic tools backed by fixtures.

Every tool returns a ToolResult-shaped dict and never raises for expected failures:
    {"tool", "ok", "mode", "data", "error", "error_type", "latency_ms"}

Mode resolution: runtime Controls (if not "ok") > fixture tool_overrides > "ok".
Modes: ok | error | slow  (+ fixture-only "timeout", which fails like an error).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from app.controls import controls
from app.services import fixtures


class ToolError(Exception):
    def __init__(self, message: str, error_type: str = "error") -> None:
        super().__init__(message)
        self.error_type = error_type


def _resolve_mode(tool: str, user_id: str | None) -> str:
    runtime = controls.tool_mode(tool)
    if runtime != "ok":
        return runtime
    return fixtures.fixture_tool_override(user_id, tool) or "ok"


def _require_user(user_id: str) -> dict[str, Any]:
    user = fixtures.get_user(user_id)
    if user is None:
        raise ToolError(f"unknown user_id: {user_id}", "not_found")
    return user


async def _run(tool: str, user_id: str | None, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    start = time.perf_counter()
    mode = _resolve_mode(tool, user_id)
    result: dict[str, Any] = {"tool": tool, "ok": False, "mode": mode, "data": None,
                              "error": None, "error_type": None, "latency_ms": 0.0}
    try:
        if mode == "error":
            await asyncio.sleep(0)
            raise ToolError(f"{tool}: simulated backend failure", "error")
        if mode == "timeout":
            await asyncio.sleep(0)
            raise ToolError(f"{tool}: upstream probe timed out", "timeout")
        if mode == "slow":
            await asyncio.sleep(controls.slow_delay_s)
        else:
            await asyncio.sleep(0)
        result["data"] = fn()
        result["ok"] = True
    except ToolError as e:
        result["error"] = str(e)
        result["error_type"] = e.error_type
    result["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
    return result


async def check_account_status(user_id: str) -> dict[str, Any]:
    def fn() -> dict[str, Any]:
        u = _require_user(user_id)
        return {"user_id": user_id, "name": u["name"], "email": u["email"], **u["account"]}
    return await _run("check_account_status", user_id, fn)


async def check_vpn_status(user_id: str) -> dict[str, Any]:
    def fn() -> dict[str, Any]:
        u = _require_user(user_id)
        return {"user_id": user_id, **u["vpn"]}
    return await _run("check_vpn_status", user_id, fn)


async def check_device_status(user_id: str) -> dict[str, Any]:
    def fn() -> dict[str, Any]:
        u = _require_user(user_id)
        return {"user_id": user_id, **u["device"]}
    return await _run("check_device_status", user_id, fn)


async def check_network_status(user_id: str) -> dict[str, Any]:
    def fn() -> dict[str, Any]:
        u = _require_user(user_id)
        return {"user_id": user_id, **u["network"]}
    return await _run("check_network_status", user_id, fn)


async def search_it_knowledge(query: str, user_id: str | None = None) -> dict[str, Any]:
    def fn() -> dict[str, Any]:
        q = (query or "").lower()
        matches = []
        for art in fixtures.get_kb_articles():
            hits = [k for k in art["keywords"] if k in q]
            if hits:
                matches.append({
                    "id": art["id"], "title": art["title"], "cause": art["cause"],
                    "resolution_steps": art["resolution_steps"],
                    "applies_when": art.get("applies_when", {}),
                    "matched_keywords": hits, "score": len(hits),
                })
        matches.sort(key=lambda m: m["score"], reverse=True)
        return {"query": query, "matches": matches}
    return await _run("search_it_knowledge", user_id, fn)


TOOLS = {
    "check_account_status": check_account_status,
    "check_vpn_status": check_vpn_status,
    "check_device_status": check_device_status,
    "check_network_status": check_network_status,
    "search_it_knowledge": search_it_knowledge,
}
