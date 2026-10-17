"""Scenario Runner view helpers for Gradio UI Tab 6."""
from __future__ import annotations

import copy
from typing import Any

from app.controls import controls
from app.services.scenarios import SCENARIOS, run_scenario

RUNNABLE_SCENARIOS: list[str] = [
    "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"
]

# In-memory store of executed scenario results to enable clicking a row to view its trace in Tab 2
LAST_SCENARIO_RESULTS: dict[str, dict[str, Any]] = {}


def _format_checks_summary(checks: dict[str, bool], sc_key_checks: list[str]) -> str:
    """Combines key checks and execution boolean checks into readable bullet points."""
    parts = []
    for k, v in checks.items():
        symbol = "[OK]" if v else "[FAIL]"
        parts.append(f"{symbol} {k}")
    if sc_key_checks:
        for kc in sc_key_checks[:2]:
            parts.append(f"• {kc}")
    return " | ".join(parts)


def run_single_scenario_ui(case_id: str) -> tuple[list[list[str]], dict[str, Any], str]:
    """Runs a single scenario, starts from a clean state, restores controls, and updates results table."""
    # Preserve current runtime controls
    saved_ks = controls.kill_switch
    saved_af = controls.agent_service_fault
    saved_tools = copy.deepcopy(controls.tool_modes)
    saved_tb = controls.troubleshooter_behavior

    try:
        res = run_scenario(case_id)
        LAST_SCENARIO_RESULTS[case_id] = res

        sc = SCENARIOS.get(case_id)
        inp = sc.messages[0] if sc and sc.messages else "-"
        key_checks = _format_checks_summary(res.get("checks", {}), sc.key_checks if sc else [])

        row = [
            case_id,
            inp,
            res.get("expected_outcome", "-"),
            res.get("actual_outcome", "-"),
            res.get("status", "FAIL"),
            key_checks,
        ]

        summary_msg = f"Scenario {case_id} executed: {res.get('status')} (Actual outcome: {res.get('actual_outcome')})"
        return [row], res.get("result", {}), summary_msg
    finally:
        # Restore controls
        controls.kill_switch = saved_ks
        controls.set_agent_service_fault(saved_af)
        controls.tool_modes = saved_tools
        controls.troubleshooter_behavior = saved_tb


def run_all_scenarios_ui() -> tuple[list[list[str]], dict[str, Any], str]:
    """Runs all scenarios (C1-C11) sequentially from a clean state and restores controls."""
    saved_ks = controls.kill_switch
    saved_af = controls.agent_service_fault
    saved_tools = copy.deepcopy(controls.tool_modes)
    saved_tb = controls.troubleshooter_behavior

    rows: list[list[str]] = []
    pass_count = 0
    first_res: dict[str, Any] = {}

    try:
        for cid in RUNNABLE_SCENARIOS:
            res = run_scenario(cid)
            LAST_SCENARIO_RESULTS[cid] = res
            if not first_res and res.get("result"):
                first_res = res["result"]

            sc = SCENARIOS.get(cid)
            inp = sc.messages[0] if sc and sc.messages else "-"
            key_checks = _format_checks_summary(res.get("checks", {}), sc.key_checks if sc else [])

            status = res.get("status", "FAIL")
            if status == "PASS":
                pass_count += 1

            rows.append([
                cid,
                inp,
                res.get("expected_outcome", "-"),
                res.get("actual_outcome", "-"),
                status,
                key_checks,
            ])

        summary_msg = f"All {len(RUNNABLE_SCENARIOS)} scenarios completed: {pass_count}/{len(RUNNABLE_SCENARIOS)} PASSED."
        return rows, first_res, summary_msg
    finally:
        controls.kill_switch = saved_ks
        controls.set_agent_service_fault(saved_af)
        controls.tool_modes = saved_tools
        controls.troubleshooter_behavior = saved_tb


def get_scenario_result_by_case(case_id: str) -> dict[str, Any] | None:
    """Retrieves full incident result dictionary for a previously run scenario."""
    sc_data = LAST_SCENARIO_RESULTS.get(case_id)
    if sc_data:
        return sc_data.get("result") or {"trace": sc_data.get("trace", []), "outcome": sc_data.get("actual_outcome")}
    return None
