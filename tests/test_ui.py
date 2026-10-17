"""Headless smoke tests for Gradio UI (Tab 1 Employee Chat & Tab 2 Live Flow Trace + Flow Map)."""
from __future__ import annotations

import asyncio
import pytest
import gradio as gr

from app.controls import controls
from app.services.data import reset_data
from ui.app import (
    EMPLOYEE_CHOICES,
    SCENARIOS_DATA,
    app,
    apply_scenario_fill,
    new_session,
    process_user_message,
)
from ui.flow_map import render_flow_map
from ui.timeline import render_timeline
from ui.it_staff import (
    get_alerts_table_data,
    get_outbox_table_data,
    get_tickets_table_data,
    render_human_review_queue_html,
    render_ticket_detail,
)
from ui.audit_view import (
    get_audit_table_data,
    render_audit_detail,
)
from ui.controls_view import render_controls_status_html
from ui.scenario_runner import (
    RUNNABLE_SCENARIOS,
    get_scenario_result_by_case,
    run_all_scenarios_ui,
    run_single_scenario_ui,
)
from app.services.accessors import reset_all_data, reset_rate_limit, set_fault, set_kill_switch


@pytest.fixture(autouse=True)
def _clean():
    reset_data()
    controls.reset()
    yield
    reset_data()
    controls.reset()


def run_async(coro):
    return asyncio.run(coro)


def test_ui_import_and_structure():
    """Verify UI imports cleanly and exposes a Gradio Blocks instance."""
    assert isinstance(app, gr.Blocks)
    assert len(EMPLOYEE_CHOICES) == 8
    assert any("custom_unknown" in c for c in EMPLOYEE_CHOICES)


def test_ui_smoke_send_message():
    """Headless smoke test: sends one message and verifies employee reply, status card, flow map, and timeline."""
    choice = EMPLOYEE_CHOICES[0]  # emp_001
    msg = "VPN keeps disconnecting every few minutes with auth timeout"
    session_id = "test-smoke-session-1"

    history, card_html, flow_map_html, timeline_html, result, cleared_input = run_async(process_user_message(
        employee_choice=choice,
        message=msg,
        history=[],
        session_id=session_id,
    ))

    # Chatbot history assertions
    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert history[0]["content"] == msg
    assert history[1]["role"] == "assistant"
    assert "VPN" in history[1]["content"] or "client" in history[1]["content"]
    assert cleared_input == ""

    # Status card HTML assertions
    assert "Incident Status" in card_html
    assert "AUTO RESOLVED" in card_html
    assert result["ticket_id"] in card_html

    # Flow Map assertions
    assert "Interactive Architecture Flow Map" in flow_map_html
    assert "Auto-Resolved" in flow_map_html
    assert "glow-outcome" in flow_map_html
    assert "check_vpn_status" in flow_map_html

    # Timeline assertions
    assert "Execution Pipeline Trace" in timeline_html
    assert "Parallel Diagnostic Workers" in timeline_html
    assert "Evaluator-Optimizer Loop" in timeline_html
    assert "Raw Result JSON" in timeline_html

    # Result state assertions
    assert result["outcome"] == "auto_resolved"
    assert result["status"] == 200
    assert result["ticket_id"] is not None
    assert len(result.get("trace", [])) > 0

    # Extended smoke test: execute a benchmark scenario through Tab 6 Scenario Runner
    sc_rows, sc_res, sc_msg = run_single_scenario_ui("C1")
    assert len(sc_rows) == 1
    assert sc_rows[0][0] == "C1"
    assert sc_rows[0][4] == "PASS"
    assert sc_rows[0][3] == "auto_resolved"
    assert sc_res.get("outcome") == "auto_resolved"
    assert "C1 executed: PASS" in sc_msg


def test_ui_unknown_user_triggers_401():
    """Verify that selecting custom/unknown user routes to 401 path with friendly error."""
    choice = "custom_unknown - Unknown User (triggers 401)"
    msg = "Can you check my access?"
    session_id = "test-smoke-session-401"

    history, card_html, flow_map_html, timeline_html, result, _ = run_async(process_user_message(
        employee_choice=choice,
        message=msg,
        history=[],
        session_id=session_id,
    ))

    assert len(history) == 2
    assert history[0]["role"] == "user"
    assert history[1]["role"] == "assistant"
    assert "401" in history[1]["content"]
    assert "Unauthorized" in history[1]["content"]

    assert result["status"] == 401
    assert result["outcome"] == "unauthorized"
    assert "401 UNAUTHORIZED" in card_html
    assert "BLOCKED" in timeline_html
    assert "Interactive Architecture Flow Map" in flow_map_html


def test_ui_multi_turn_session_reuse():
    """Verify multi-turn conversation maintains session and appends on same ticket (C2 pattern)."""
    choice = "emp_007 - Grace Kim (LT-007)"
    session_id = "test-session-multiturn"

    # Turn 1: vague report -> needs_more_info
    hist1, _, _, _, res1, _ = run_async(process_user_message(
        employee_choice=choice,
        message="my laptop is broken",
        history=[],
        session_id=session_id,
    ))
    assert len(hist1) == 2
    assert res1["outcome"] == "needs_more_info"
    ticket_id = res1["ticket_id"]
    assert ticket_id is not None

    # Turn 2: follow-up in same session -> appends to same ticket
    hist2, _, _, _, res2, _ = run_async(process_user_message(
        employee_choice=choice,
        message="The screen is completely black and won't turn on",
        history=hist1,
        session_id=session_id,
    ))
    assert len(hist2) == 4
    assert res2["ticket_id"] == ticket_id


def test_ui_new_session_resets_state():
    """Verify New Session button returns fresh empty state and new session ID."""
    history, card_html, flow_map_html, timeline_html, result, new_sid = new_session()
    assert history == []
    assert result == {}
    assert "IDLE" in card_html
    assert "IDLE - Send message to trace" in flow_map_html
    assert "No Live Flow Trace Available" in timeline_html
    assert len(new_sid) > 0


def test_ui_scenario_quick_fill():
    """Verify scenario quick-fill buttons populate choices and configure controls."""
    assert len(SCENARIOS_DATA) == 11
    # Check C3 configures hallucinate_once
    choice, msg = apply_scenario_fill("C3")
    assert "emp_002" in choice
    assert "locked out" in msg
    assert controls.troubleshooter_behavior == "hallucinate_once"

    # Check C10 configures agent_fault
    choice10, msg10 = apply_scenario_fill("C10")
    assert "emp_001" in choice10
    assert controls.agent_fault is True


# ===========================================================================
# Timeline Specific Tests: C1 (simple), C3 (retry loop), C8 (tool error)
# ===========================================================================

def test_timeline_empty_state():
    """Verify empty-state message when there is no request yet."""
    html_none = render_timeline(None)
    assert "No Live Flow Trace Available" in html_none
    html_empty_dict = render_timeline({})
    assert "No Live Flow Trace Available" in html_empty_dict


def test_timeline_c1_simple_path():
    """Verify C1 simple path: step badges, Yes/No decision branches, workers, approved attempt 1, raw JSON."""
    choice, msg = apply_scenario_fill("C1")
    _, _, _, html, res, _ = run_async(process_user_message(choice, msg, [], "sid-test-c1"))

    # Step types and badges
    assert "CODE / API" in html
    assert "LLM AGENT" in html
    assert "DECISION" in html

    # Decision branches (Yes/No)
    assert "branch-yes" in html or "branch-no" in html
    assert "Yes" in html

    # Parallel workers group
    assert "Parallel Diagnostic Workers" in html
    assert "check_vpn_status" in html or "Network" in html
    assert "status-pill-ok" in html

    # Evaluator loop: Attempt 1 approved
    assert "Evaluator-Optimizer Loop" in html
    assert "Attempt 1" in html
    assert "APPROVED" in html
    assert "Troubleshooter Draft Proposal" in html

    # Raw JSON collapsible section
    assert "<details" in html
    assert "Raw Result JSON" in html
    assert "auto_resolved" in html


def test_timeline_c3_evaluator_loop_retry():
    """Verify C3 retry loop: attempt 1 rejected (with issues, critique) -> attempt 2 approved."""
    choice, msg = apply_scenario_fill("C3")
    _, _, _, html, res, _ = run_async(process_user_message(choice, msg, [], "sid-test-c3"))

    assert "Evaluator-Optimizer Loop" in html
    assert "Attempt 1" in html
    assert "REJECTED" in html
    assert "Issues Detected" in html
    assert "Critique Feedback for Next Attempt" in html

    assert "Attempt 2" in html
    assert "APPROVED" in html
    assert res["outcome"] == "auto_resolved"


def test_timeline_c8_parallel_workers_error():
    """Verify C8 tool error: check_network_status failure shown with error/timeout pill and latency."""
    choice, msg = apply_scenario_fill("C8")
    _, _, _, html, res, _ = run_async(process_user_message(choice, msg, [], "sid-test-c8"))

    assert "Parallel Diagnostic Workers" in html
    assert "check_network_status" in html
    assert "TIMEOUT" in html or "ERROR" in html
    assert "status-pill-timeout" in html or "status-pill-error" in html
    assert "upstream probe timed out" in html
    assert "unresolved_handoff_L2" in html
    assert res["outcome"] == "unresolved_handoff_L2"


# ===========================================================================
# Flow Map Specific Tests: C1, C5, C6, C10 & Resilience
# ===========================================================================

def test_flow_map_c1_simple_path():
    """Verify C1 flow map: highlights auto-resolved box, parallel workers with OK tools, and active path."""
    choice, msg = apply_scenario_fill("C1")
    _, _, flow_svg, _, res, _ = run_async(process_user_message(choice, msg, [], "sid-flow-c1"))

    assert "Interactive Architecture Flow Map" in flow_svg
    assert "Auto-Resolved" in flow_svg
    assert "glow-outcome" in flow_svg
    assert "check_vpn_status" in flow_svg
    assert "OK" in flow_svg
    assert res["outcome"] == "auto_resolved"


def test_flow_map_c5_escalation_path():
    """Verify C5 flow map: highlights immediate_alert and escalated_to_human outcome box."""
    choice, msg = apply_scenario_fill("C5")
    _, _, flow_svg, _, res, _ = run_async(process_user_message(choice, msg, [], "sid-flow-c5"))

    assert "Escalated to Human" in flow_svg
    assert "glow-outcome" in flow_svg
    assert "SOC / On-Call Alert" in flow_svg
    assert res["outcome"] == "escalated_to_human"


def test_flow_map_c6_blocked_path():
    """Verify C6 flow map: highlights input_guardrail and blocked_by_guardrail box, greying out agent stages."""
    choice, msg = apply_scenario_fill("C6")
    _, _, flow_svg, _, res, _ = run_async(process_user_message(choice, msg, [], "sid-flow-c6"))

    assert "Blocked by Guardrail" in flow_svg
    assert "glow-outcome" in flow_svg
    assert "Input Guardrail" in flow_svg
    assert res["outcome"] == "blocked_by_guardrail"


def test_flow_map_c10_error_path():
    """Verify C10 flow map: highlights System Error (WF-ERR) box and greys out agent service."""
    choice, msg = apply_scenario_fill("C10")
    _, _, flow_svg, _, res, _ = run_async(process_user_message(choice, msg, [], "sid-flow-c10"))

    assert "System Error (WF-ERR)" in flow_svg
    assert "glow-outcome" in flow_svg
    assert res["outcome"] == "system_error"


def test_flow_map_resilient_unknown_step():
    """Verify that unknown trace steps are safely ignored without crashing."""
    dummy_result = {
        "outcome": "auto_resolved",
        "trace": [
            {"step": "receive_request", "type": "code"},
            {"step": "unknown_future_step_xyz", "type": "code"},
            {"step": "auth", "type": "code"},
        ],
    }
    svg = render_flow_map(dummy_result)
    assert "Interactive Architecture Flow Map" in svg
    assert "Auto-Resolved" in svg


def test_tab3_and_tab4_c5_and_c1_verification():
    """PART 10 Verification:

    Run C5 and C1:
    - C5 appears in human review queue and alerts.
    - C5 draft resolution proposal is strictly absent from the employee outbox.
    - C1 appears as auto_resolved, in outbox, but not in review queue.
    - Tab 4 displays audit records with filters, showing secret redactions.
    """
    # 1. Run C5 (emp_005: phishing credentials -> escalated_to_human)
    c5_choice, c5_msg = apply_scenario_fill("C5")
    _, _, _, _, c5_res, _ = run_async(process_user_message(
        employee_choice=c5_choice,
        message=c5_msg,
        history=[],
        session_id="session-tab34-c5",
    ))
    assert c5_res["outcome"] == "escalated_to_human"
    c5_ticket_id = c5_res["ticket_id"]
    assert c5_ticket_id is not None

    # 2. Run C1 (emp_001: VPN drops -> auto_resolved)
    c1_choice, c1_msg = apply_scenario_fill("C1")
    _, _, _, _, c1_res, _ = run_async(process_user_message(
        employee_choice=c1_choice,
        message=c1_msg,
        history=[],
        session_id="session-tab34-c1",
    ))
    assert c1_res["outcome"] == "auto_resolved"
    c1_ticket_id = c1_res["ticket_id"]
    assert c1_ticket_id is not None

    # 3. TAB 3: Tickets Table
    ticket_rows = get_tickets_table_data()
    assert len(ticket_rows) >= 2
    ticket_ids = [r[0] for r in ticket_rows]
    assert c5_ticket_id in ticket_ids
    assert c1_ticket_id in ticket_ids

    # Find C5 row and check flags
    c5_row = next(r for r in ticket_rows if r[0] == c5_ticket_id)
    assert "P1" in c5_row[4] or "NEEDS-MANUAL" in c5_row[4]
    assert c5_row[1] == "emp_005"

    # Ticket detail view for C5 and C1
    c5_detail_html = render_ticket_detail(c5_ticket_id)
    assert c5_ticket_id in c5_detail_html
    assert "emp_005" in c5_detail_html
    assert "INTERNAL TECHNICIAN NOTE" in c5_detail_html

    c1_detail_html = render_ticket_detail(c1_ticket_id)
    assert c1_ticket_id in c1_detail_html
    assert "emp_001" in c1_detail_html

    # Empty detail view
    empty_detail_html = render_ticket_detail(None)
    assert "No Ticket Selected" in empty_detail_html

    # 4. TAB 3: Human Review Queue
    review_queue_html = render_human_review_queue_html()
    # C5 MUST appear in the review queue
    assert c5_ticket_id in review_queue_html
    assert "emp_005" in review_queue_html
    assert "ESCALATED TO HUMAN" in review_queue_html
    # Must prominently state that draft was NOT sent to employee
    assert "NOT sent to the employee" in review_queue_html
    # C1 must NOT be in the review queue
    assert c1_ticket_id not in review_queue_html

    # 5. TAB 3: Alerts Table
    alert_rows = get_alerts_table_data()
    assert len(alert_rows) > 0
    # C5 SOC alert must appear
    c5_alerts = [a for a in alert_rows if a[2] == c5_ticket_id]
    assert len(c5_alerts) >= 1
    # Check channel and timing
    soc_alert = next((a for a in c5_alerts if a[1] == "SOC"), None)
    assert soc_alert is not None
    assert soc_alert[4] == "PRE-DIAGNOSTIC"

    # 6. TAB 3: Outbox Table (Every message sent to employees)
    outbox_rows = get_outbox_table_data()
    assert len(outbox_rows) > 0
    outbox_ticket_ids = [o[1] for o in outbox_rows]
    assert c1_ticket_id in outbox_ticket_ids
    assert c5_ticket_id in outbox_ticket_ids

    # Critical requirement: C5 draft resolution proposal is strictly absent from the outbox
    c5_outbox_msgs = [o[5] for o in outbox_rows if o[1] == c5_ticket_id]
    # In C5, only the holding template was sent to employee
    for msg in c5_outbox_msgs:
        assert "specialist for review" in msg or "passed to a specialist" in msg or "ticket has been escalated" in msg
        # Internal diagnostic recommendations or draft claims must NOT be in outbox
        assert "Diagnostic checks ran" not in msg
        assert "Drafted Resolution" not in msg

    # 7. TAB 4: SQLite Audit Log
    audit_rows = get_audit_table_data()
    assert len(audit_rows) >= 2

    # Filtering by outcome
    c5_filtered = get_audit_table_data(outcome="escalated_to_human")
    assert any(r[2] == c5_ticket_id for r in c5_filtered)
    assert not any(r[2] == c1_ticket_id for r in c5_filtered)

    c1_filtered = get_audit_table_data(outcome="auto_resolved")
    assert any(r[2] == c1_ticket_id for r in c1_filtered)
    assert not any(r[2] == c5_ticket_id for r in c1_filtered)

    # Filtering by user
    emp5_filtered = get_audit_table_data(user="emp_005")
    assert all(r[3] == "emp_005" for r in emp5_filtered)

    # Filtering by security flag
    flagged_rows = get_audit_table_data(sec_flag="Flagged")
    assert any(r[2] == c5_ticket_id for r in flagged_rows)
    assert not any(r[2] == c1_ticket_id for r in flagged_rows)

    # Selecting an audit record shows full JSON
    c5_audit_row = next(r for r in audit_rows if r[2] == c5_ticket_id)
    c5_audit_id = int(c5_audit_row[0])
    c5_audit_detail = render_audit_detail(c5_audit_id)
    assert f"Audit Record #{c5_audit_id}" in c5_audit_detail
    assert c5_ticket_id in c5_audit_detail
    assert "ESCALATED TO HUMAN" in c5_audit_detail

    # Test secret redaction marker on a message containing sensitive credentials
    _, _, _, _, secret_res, _ = run_async(process_user_message(
        employee_choice="emp_002 - Bilal Haddad (LT-002)",
        message="my password is SecretHunter999 and token sk-1234567890abcdef",
        history=[],
        session_id="session-secret-redact",
    ))
    secret_audit_rows = get_audit_table_data(user="emp_002")
    assert len(secret_audit_rows) > 0
    secret_audit_id = int(secret_audit_rows[0][0])
    secret_detail_html = render_audit_detail(secret_audit_id)
    assert "SECRET REDACTION VERIFIED" in secret_detail_html
    assert "[REDACTED]" in secret_detail_html
    assert "SecretHunter999" not in secret_detail_html


def test_tab5_controls_fault_injection():
    """Verify Tab 5 controls view: kill switch, agent fault modes, tool modes, and resets."""
    # 1. Kill switch
    set_kill_switch(True)
    assert controls.kill_switch is True
    html_status = render_controls_status_html()
    assert "ON (AGENT BLOCKED)" in html_status

    set_kill_switch(False)
    assert controls.kill_switch is False
    assert "OFF (NORMAL)" in render_controls_status_html()

    # 2. Agent service faults (none / timeout / exception / invalid response)
    for fault in ("timeout", "exception", "invalid response"):
        set_fault("agent_service_fault", fault)
        assert controls.agent_service_fault == fault
        assert controls.agent_fault is True
        assert fault.upper() in render_controls_status_html()

    set_fault("agent_service_fault", "none")
    assert controls.agent_service_fault == "none"
    assert controls.agent_fault is False
    assert "NONE (HEALTHY)" in render_controls_status_html()

    # 3. Troubleshooter behavior
    set_fault("troubleshooter_behavior", "hallucinate_once")
    assert controls.troubleshooter_behavior == "hallucinate_once"
    assert "HALLUCINATE ONCE" in render_controls_status_html()

    set_fault("troubleshooter_behavior", "hallucinate_always")
    assert controls.troubleshooter_behavior == "hallucinate_always"
    assert "HALLUCINATE ALWAYS" in render_controls_status_html()

    # 4. Per-tool modes for all 5 tools
    tools = [
        "check_account_status",
        "check_vpn_status",
        "check_device_status",
        "check_network_status",
        "search_it_knowledge",
    ]
    for t in tools:
        set_fault(t, "error")
        assert controls.tool_mode(t) == "error"
        set_fault(t, "slow")
        assert controls.tool_mode(t) == "slow"
        set_fault(t, "ok")
        assert controls.tool_mode(t) == "ok"

    # 5. Reset buttons
    reset_rate_limit()
    reset_all_data()
    assert controls.kill_switch is False
    assert controls.agent_service_fault == "none"
    assert controls.troubleshooter_behavior is None


def test_tab6_scenario_runner():
    """Verify Tab 6 scenario runner: single scenario run, all scenarios run, clean state & restore."""
    # Set custom controls before running to ensure they are restored
    controls.kill_switch = True
    controls.set_agent_service_fault("exception")
    controls.set_tool_mode("check_vpn_status", "slow")

    # 1. Run single scenario C1
    rows, res, msg = run_single_scenario_ui("C1")
    assert len(rows) == 1
    assert rows[0][0] == "C1"
    assert rows[0][4] == "PASS"
    assert rows[0][3] == "auto_resolved"
    assert res.get("outcome") == "auto_resolved"
    assert "C1 executed: PASS" in msg

    # Verify controls were restored
    assert controls.kill_switch is True
    assert controls.agent_service_fault == "exception"
    assert controls.tool_mode("check_vpn_status") == "slow"

    # Verify get_scenario_result_by_case returns cached result with trace
    sc_res = get_scenario_result_by_case("C1")
    assert sc_res is not None
    assert sc_res.get("outcome") == "auto_resolved"
    assert len(sc_res.get("trace", [])) > 0

    # 2. Run all scenarios (C1 - C11)
    controls.reset()
    all_rows, first_res, all_msg = run_all_scenarios_ui()
    assert len(all_rows) == len(RUNNABLE_SCENARIOS)
    assert all(r[4] == "PASS" for r in all_rows)
    assert f"11/{len(RUNNABLE_SCENARIOS)} PASSED" in all_msg
    assert first_res.get("outcome") is not None

