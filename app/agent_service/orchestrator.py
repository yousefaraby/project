"""Step 3 & 4: Plan filtering, Incident Orchestrator (concurrent execution), and Evidence Aggregation."""
from __future__ import annotations

import asyncio
import time
from typing import Any

from app.agents.base import Worker
from app.agents.mock import (
    AccountWorker,
    DeviceWorker,
    KBWorker,
    NetworkWorker,
)
from app.controls import TOOL_NAMES

ALLOWED_TOOLS: tuple[str, ...] = TOOL_NAMES  # 5 read-only tools

CRITICAL_TOOLS_PER_CATEGORY: dict[str, list[str]] = {
    "network": ["check_network_status", "check_vpn_status"],
    "account": ["check_account_status"],
    "device": ["check_device_status"],
    "application": ["check_device_status"],
    "security": ["check_account_status", "check_device_status"],
    "unknown": ["search_it_knowledge"],
}

WORKER_REGISTRY: dict[str, type[Worker]] = {
    "Network": NetworkWorker,
    "Account": AccountWorker,
    "Device": DeviceWorker,
    "KB": KBWorker,
}


def filter_plan_tools(plan: dict[str, Any]) -> dict[str, Any]:
    """Filters plan tools to an allow-list of the 5 read-only tools. Anything else is dropped."""
    original_tools = plan.get("tools", [])
    allowed = [t for t in original_tools if t in ALLOWED_TOOLS]
    plan["tools"] = allowed
    return plan


def has_enough_evidence(category: str, successful_tools: set[str]) -> bool:
    """Checks whether the critical tools for a category succeeded."""
    cat = (category or "").lower()
    critical = CRITICAL_TOOLS_PER_CATEGORY.get(cat, ["search_it_knowledge"])

    if cat in ("network", "security"):
        # For network, needs check_network_status or check_vpn_status
        # For security, needs at least one of account or device check
        return bool(successful_tools & set(critical))
    else:
        # All required critical tools must be in successful_tools
        return all(t in successful_tools for t in critical)


class IncidentOrchestrator:
    """Runs the selected workers CONCURRENTLY with asyncio.gather and a per-tool timeout."""

    def __init__(self, per_tool_timeout_s: float = 2.0) -> None:
        self.per_tool_timeout_s = per_tool_timeout_s

    async def run(self, plan: dict[str, Any], context: dict[str, Any]) -> list[dict[str, Any]]:
        worker_names = plan.get("workers", [])
        tasks = []

        for name in worker_names:
            worker_cls = WORKER_REGISTRY.get(name)
            if not worker_cls:
                continue
            worker = worker_cls()
            worker_task = {"timeout_s": self.per_tool_timeout_s}
            tasks.append(self._safe_run_worker(worker, worker_task, context))

        if not tasks:
            return []

        # Run selected workers concurrently
        return await asyncio.gather(*tasks)

    async def _safe_run_worker(self, worker: Worker, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        t0 = time.perf_counter()
        try:
            return await asyncio.wait_for(worker.run(task, context), timeout=self.per_tool_timeout_s + 0.5)
        except asyncio.TimeoutError:
            latency = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "worker": worker.name,
                "status": "error",
                "findings": [],
                "evidence": {
                    worker.name: {
                        "tool": worker.name,
                        "ok": False,
                        "mode": "timeout",
                        "error": f"Worker {worker.name} timed out after {self.per_tool_timeout_s}s",
                        "error_type": "timeout",
                    }
                },
                "latency": latency,
            }
        except Exception as e:
            latency = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "worker": worker.name,
                "status": "error",
                "findings": [],
                "evidence": {
                    worker.name: {
                        "tool": worker.name,
                        "ok": False,
                        "mode": "error",
                        "error": str(e),
                        "error_type": "error",
                    }
                },
                "latency": latency,
            }


def aggregate_evidence(category: str, worker_results: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Plain code aggregation.

    Splits results into findings and tool_errors.
    NEVER turns an error into 'all good'.
    Evaluates enough_evidence based on critical tools for the category.
    """
    all_findings: list[str] = []
    tool_results: list[dict[str, Any]] = []
    tool_errors: list[dict[str, Any]] = []
    successful_tools: set[str] = set()
    combined_evidence: dict[str, Any] = {}

    for wr in worker_results:
        all_findings.extend(wr.get("findings", []))
        evidence = wr.get("evidence", {})
        combined_evidence[wr.get("worker", "unknown")] = evidence

        for tool_name, tool_data in evidence.items():
            if isinstance(tool_data, dict):
                if tool_data.get("ok") is False or "error" in tool_data and tool_data["error"]:
                    tool_errors.append({
                        "tool": tool_data.get("tool", tool_name),
                        "error": tool_data.get("error", "unknown error"),
                        "error_type": tool_data.get("error_type", "error"),
                    })
                elif tool_data.get("ok") is True:
                    successful_tools.add(tool_data.get("tool", tool_name))
                    tool_results.append({
                        "tool": tool_data.get("tool", tool_name),
                        "data": tool_data.get("data"),
                        "latency_ms": tool_data.get("latency_ms", 0.0),
                    })

    enough = has_enough_evidence(category, successful_tools)

    aggregated_findings = {
        "summary": all_findings,
        "evidence": combined_evidence,
    }

    return aggregated_findings, tool_results, tool_errors, enough
