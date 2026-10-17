import asyncio
import time
import pytest

from app.agent_service.orchestrator import (
    ALLOWED_TOOLS,
    IncidentOrchestrator,
    aggregate_evidence,
    filter_plan_tools,
    has_enough_evidence,
)
from app.agent_service.service import process_incident
from app.agents.mock import MockPlanner
from app.controls import controls


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. Plan per Category Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("category,expected_workers", [
    ("network", ["Network", "Device", "KB"]),
    ("account", ["Account", "KB"]),
    ("device", ["Device", "KB"]),
    ("application", ["Device", "KB"]),
    ("security", ["Account", "Device", "KB"]),
    ("unknown", ["KB"]),
])
def test_plan_per_category(category, expected_workers):
    planner = MockPlanner()
    plan = run(planner.plan({"category": category}, {}))

    assert plan["category"] == category
    assert plan["workers"] == expected_workers
    assert isinstance(plan["tools"], list)
    assert len(plan["tools"]) > 0
    # Short reasoning string present
    assert isinstance(plan["reasoning"], str)
    assert len(plan["reasoning"]) > 10
    assert category in plan["reasoning"]


# ---------------------------------------------------------------------------
# 2. Disallowed Tools Filtered Out
# ---------------------------------------------------------------------------

def test_disallowed_tool_filtered_out():
    plan = {
        "category": "security",
        "workers": ["Account", "Device", "KB"],
        "tools": [
            "check_account_status",
            "reset_password",          # Disallowed
            "disable_mfa",            # Disallowed
            "check_device_status",
            "format_hard_drive",      # Disallowed
            "search_it_knowledge",
        ],
        "reasoning": "Test plan with injected admin actions",
    }

    filtered = filter_plan_tools(plan)
    assert filtered["tools"] == [
        "check_account_status",
        "check_device_status",
        "search_it_knowledge",
    ]
    for disallowed in ["reset_password", "disable_mfa", "format_hard_drive"]:
        assert disallowed not in filtered["tools"]

    # Verify all remaining tools belong to ALLOWED_TOOLS
    assert all(t in ALLOWED_TOOLS for t in filtered["tools"])


# ---------------------------------------------------------------------------
# 3. Concurrent Worker Execution (Parallelism Benchmark)
# ---------------------------------------------------------------------------

def test_workers_run_in_parallel():
    """Verify that multiple workers run concurrently with asyncio.gather.
    Total duration must be close to the slowest tool, not the sequential sum."""
    delay = 0.25
    controls.slow_delay_s = delay
    controls.set_tool_mode("check_device_status", "slow")
    controls.set_tool_mode("search_it_knowledge", "slow")

    orchestrator = IncidentOrchestrator(per_tool_timeout_s=2.0)
    plan = {
        "workers": ["Device", "KB"],
        "tools": ["check_device_status", "search_it_knowledge"],
    }
    context = {"user_id": "emp_001", "message": "vpn issue"}

    t0 = time.perf_counter()
    results = run(orchestrator.run(plan, context))
    total_duration = time.perf_counter() - t0

    assert len(results) == 2
    for r in results:
        assert r["status"] == "ok"

    # If sequential: delay * 2 >= 0.50s.
    # Since parallel: total_duration should be close to delay (~0.25s), well under 0.45s.
    assert total_duration < (delay * 2 * 0.85), (
        f"Expected parallel execution under {delay * 2 * 0.85:.2f}s, took {total_duration:.2f}s"
    )
    assert total_duration >= (delay * 0.9)


# ---------------------------------------------------------------------------
# 4. Tool Timeout Becomes tool_errors (No Pipeline Crash)
# ---------------------------------------------------------------------------

def test_tool_timeout_becomes_tool_errors():
    controls.slow_delay_s = 0.4
    controls.set_tool_mode("check_account_status", "slow")

    # Orchestrator with aggressive 0.1s timeout
    orchestrator = IncidentOrchestrator(per_tool_timeout_s=0.1)
    plan = {"workers": ["Account"], "tools": ["check_account_status"]}
    context = {"user_id": "emp_001", "message": "account locked"}

    results = run(orchestrator.run(plan, context))
    assert len(results) == 1
    account_res = results[0]

    assert account_res["worker"] == "Account"
    assert account_res["status"] == "error"

    findings, tool_results, tool_errors, enough = aggregate_evidence("account", results)
    assert len(tool_errors) == 1
    assert tool_errors[0]["tool"] == "check_account_status"
    assert tool_errors[0]["error_type"] == "timeout"
    assert not enough  # Account is critical for account category


# ---------------------------------------------------------------------------
# 5. Enough Evidence True/False (using emp_004)
# ---------------------------------------------------------------------------

def test_enough_evidence_true_emp_004():
    """emp_004 has check_network_status failing/timing out by fixture flag.
    However, for category 'network', check_vpn_status succeeds.
    Since network needs check_network_status OR check_vpn_status,
    enough_evidence is True."""
    orchestrator = IncidentOrchestrator(per_tool_timeout_s=2.0)
    plan = {
        "workers": ["Network", "Device", "KB"],
        "tools": ["check_network_status", "check_vpn_status", "check_device_status", "search_it_knowledge"],
    }
    context = {"user_id": "emp_004", "message": "VPN connection drops"}

    results = run(orchestrator.run(plan, context))
    findings, tool_results, tool_errors, enough = aggregate_evidence("network", results)

    # check_network_status failed
    failed_tools = [e["tool"] for e in tool_errors]
    assert "check_network_status" in failed_tools

    # check_vpn_status succeeded
    ok_tools = [r["tool"] for r in tool_results]
    assert "check_vpn_status" in ok_tools

    # Because check_vpn_status succeeded, enough_evidence is True
    assert enough is True


def test_enough_evidence_false_emp_004_and_process_incident():
    """When both network probes fail on emp_004 (check_network_status via fixture,
    and check_vpn_status via simulated error), enough_evidence is False.
    The incident must end as unresolved_handoff_L2 with partial findings and
    tool_errors attached."""
    controls.set_tool_mode("check_vpn_status", "error")

    incident = {
        "incident_id": "INC-0404",
        "user_id": "emp_004",
        "message": "VPN connection drops repeatedly on my Mac",
        "idempotency_key": "INC-0404:msg1",
    }

    res = run(process_incident(incident, {}))

    assert res["outcome"] == "unresolved_handoff_L2"
    assert res["requires_human"] is True

    # Both tools recorded in tool_errors
    tool_err_names = [e["tool"] for e in res["tool_errors"]]
    assert "check_network_status" in tool_err_names
    assert "check_vpn_status" in tool_err_names

    # Never turn error into all good: tool_errors has entries
    assert len(res["tool_errors"]) >= 2

    # Partial findings are preserved
    assert "findings" in res
    assert "triage" in res["findings"]

    # Trace shows the plan, workers, and aggregate step
    step_names = [t["step"] for t in res["trace"]]
    assert "plan" in step_names
    assert "worker_Network" in step_names
    assert "aggregate_evidence" in step_names
    assert "evidence_check" in step_names

    # Check aggregate step details in trace
    agg_trace = [t for t in res["trace"] if t["step"] == "aggregate_evidence"][0]
    assert agg_trace["type"] == "decision"
    assert agg_trace["branch"] == "not_enough"
