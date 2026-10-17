"""Vertical live flow trace timeline renderer for Gradio UI Tab 2."""
from __future__ import annotations

import html
import json
from typing import Any

from ui.theme import (
    COLOR_BLOCKED_FAILED,
    COLOR_CODE_API,
    COLOR_DECISION,
    COLOR_HUMAN_LOOP,
    COLOR_LLM_AGENT,
    COLOR_SUCCESS,
)

# Friendly step title mapping
STEP_TITLES: dict[str, str] = {
    "receive_request": "Receive HTTP Request",
    "auth": "Bearer Token Authentication",
    "rate_limit": "Sliding-Window Rate Limiter",
    "kill_switch": "Emergency Kill Switch Check",
    "load_session": "Load Session State & History",
    "ticket": "Ticket Routing (Create / Append)",
    "agent_call": "Agent Client Invocation",
    "validate_response": "Response Schema Validation",
    "input_guardrail": "Input Security Guardrail",
    "keyword_scan": "Bilingual Security Keyword Scan",
    "triage": "Triage Agent (Mock LLM)",
    "missing_info_check": "Missing Info Gate",
    "routing_rules": "Escalation Routing Rules",
    "immediate_alert": "Immediate High-Priority Alert",
    "plan": "Planner Agent (Allowlist Filtered)",
    "aggregate_evidence": "Aggregate Diagnostics Evidence",
    "evidence_check": "Critical Diagnostics Sufficiency Check",
    "hard_rule_override": "Hard Rule Safety Override",
    "action_tools": "Remediation Action Execution",
    "outcome_switch": "Outcome Routing Switch",
    "outcome_auto_resolved": "Outcome: Auto-Resolved",
    "outcome_needs_more_info": "Outcome: Needs More Info",
    "outcome_escalated_to_human": "Outcome: Escalated to Human",
    "outcome_unresolved_handoff_L2": "Outcome: Handoff to L2 Support",
    "outcome_blocked_by_guardrail": "Outcome: Blocked by Guardrail",
    "outcome_action_failed": "Outcome: Action Execution Failed",
    "write_audit": "Write SQLite Audit Log Record",
    "update_session": "Update Session Memory & Incident ID",
    "WF-ERR": "Workflow Failure Handler (WF-ERR)",
}

STEP_TYPE_BADGES: dict[str, tuple[str, str]] = {
    "code": ("CODE / API", COLOR_CODE_API),
    "llm": ("LLM AGENT", COLOR_LLM_AGENT),
    "decision": ("DECISION", COLOR_DECISION),
    "human": ("HUMAN REVIEW", COLOR_HUMAN_LOOP),
    "blocked": ("BLOCKED", COLOR_BLOCKED_FAILED),
}


def _esc(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


def _format_decision_branch(step: str, branch: str | None) -> str:
    if not branch:
        return ""
    b_lower = str(branch).lower()

    if step == "kill_switch":
        is_yes = "human" in b_lower
        label = "Yes (Kill switch active)" if is_yes else "No (Normal operation)"
        cls = "branch-warn" if is_yes else "branch-yes"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if step == "missing_info_check":
        is_yes = "needs_more_info" in b_lower
        label = "Yes (Ask user)" if is_yes else "No (Continue)"
        cls = "branch-warn" if is_yes else "branch-yes"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if step == "routing_rules":
        is_yes = "requires_human" in b_lower
        label = "Yes (Requires human)" if is_yes else "No (Agent continues)"
        cls = "branch-warn" if is_yes else "branch-yes"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if step in ("aggregate_evidence", "evidence_check"):
        is_yes = "enough" in b_lower and "not" not in b_lower
        label = "Yes (Enough evidence)" if is_yes else "No (Critical tools failed)"
        cls = "branch-yes" if is_yes else "branch-no"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if "verdict" in step:
        is_yes = "approved" in b_lower
        label = "Yes (Approved)" if is_yes else "No (Rejected)"
        cls = "branch-yes" if is_yes else "branch-no"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if step == "evaluator_loop":
        is_yes = "approved" in b_lower
        label = "Yes (Approved within attempts)" if is_yes else "No (Loop exhausted)"
        cls = "branch-yes" if is_yes else "branch-no"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if step == "validate_response":
        is_yes = "valid" in b_lower and "invalid" not in b_lower
        label = "Yes (Valid schema)" if is_yes else "No (Invalid)"
        cls = "branch-yes" if is_yes else "branch-no"
        return f'<span class="decision-branch {cls}">{label}</span>'

    if step == "ticket":
        is_yes = "append" in b_lower
        label = "Yes (Append to open ticket)" if is_yes else "No (Create new ticket)"
        cls = "branch-yes" if is_yes else "branch-info"
        return f'<span class="decision-branch {cls}">{label}</span>'

    # Fallback Yes/No detection
    if b_lower in ("yes", "approved", "pass", "valid", "clean", "enough", "ok", "true"):
        return f'<span class="decision-branch branch-yes">Yes ({_esc(branch)})</span>'
    elif b_lower in ("no", "rejected", "block", "invalid", "not_enough", "exhausted", "error", "false"):
        return f'<span class="decision-branch branch-no">No ({_esc(branch)})</span>'
    return f'<span class="decision-branch branch-info">Branch: {_esc(branch)}</span>'


def _render_standard_step(step: dict[str, Any]) -> str:
    name = step.get("step", "")
    stype = step.get("type", "code")
    badge_label, badge_color = STEP_TYPE_BADGES.get(stype, ("CODE", COLOR_CODE_API))
    title = STEP_TITLES.get(name, name.replace("_", " ").title())
    duration_ms = step.get("duration_ms", 0.0)
    dur_str = f"{duration_ms:.2f} ms" if duration_ms > 0 else "<0.1 ms"

    branch_html = ""
    if stype == "decision":
        branch_html = _format_decision_branch(name, step.get("branch"))

    input_val = step.get("input", "")
    output_val = step.get("output", "")

    io_html = ""
    if input_val or output_val:
        io_html = f"""
        <div class="step-io-grid">
            <div class="step-io-row">
                <span class="step-io-tag">INPUT</span>
                <span class="step-io-content">{_esc(input_val)}</span>
            </div>
            <div class="step-io-row">
                <span class="step-io-tag">OUTPUT</span>
                <span class="step-io-content">{_esc(output_val)}</span>
            </div>
        </div>
        """

    return f"""
    <div class="timeline-item">
        <div class="timeline-dot" style="border-color: {badge_color};"></div>
        <div class="timeline-card">
            <div class="timeline-card-header">
                <div class="step-title-group">
                    <span class="step-title">{_esc(title)}</span>
                    <span class="step-badge" style="background-color: {badge_color};">{badge_label}</span>
                    {branch_html}
                </div>
                <span class="step-duration">{dur_str}</span>
            </div>
            {io_html}
        </div>
    </div>
    """


def _render_parallel_workers_card(
    worker_steps: list[dict[str, Any]],
    tool_results: list[dict[str, Any]] | None,
    tool_errors: list[dict[str, Any]] | None,
) -> str:
    total_duration = max((s.get("duration_ms", 0.0) for s in worker_steps), default=0.0)
    dur_str = f"{total_duration:.2f} ms" if total_duration > 0 else "<0.1 ms"

    # Merge worker steps, tool_results, and tool_errors
    items_html = []

    # Map tool errors by tool name
    errors_map = {e.get("tool"): e for e in (tool_errors or [])}
    success_map = {r.get("tool"): r for r in (tool_results or [])}

    # If structured tool results are available, show each tool
    if success_map or errors_map:
        for tool_name, err in errors_map.items():
            err_type = err.get("error_type", "error").lower()
            pill_class = "status-pill-timeout" if "timeout" in err_type else "status-pill-error"
            pill_label = "TIMEOUT" if "timeout" in err_type else "ERROR"
            err_msg = err.get("error", "tool failed")

            items_html.append(f"""
            <div class="worker-sub-row error-row">
                <div class="worker-tool-meta">
                    <span class="worker-tool-name">{_esc(tool_name)}</span>
                    <span class="{pill_class}">{pill_label}</span>
                </div>
                <div class="worker-details-text">{_esc(err_msg)}</div>
            </div>
            """)

        for tool_name, res in success_map.items():
            lat = res.get("latency_ms", 0.0)
            lat_str = f"{lat:.2f} ms" if lat else "<0.1 ms"

            items_html.append(f"""
            <div class="worker-sub-row success-row">
                <div class="worker-tool-meta">
                    <span class="worker-tool-name">{_esc(tool_name)}</span>
                    <span class="status-pill-ok">OK</span>
                </div>
                <div class="worker-details-text">Latency: {lat_str} | Diagnostic data collected</div>
            </div>
            """)
    else:
        # Fallback to worker_steps from trace
        for ws in worker_steps:
            w_name = ws.get("input") or ws.get("step", "").replace("worker_", "")
            branch = ws.get("branch", "ok")
            dur = ws.get("duration_ms", 0.0)
            dur_str_sub = f"{dur:.2f} ms" if dur > 0 else "<0.1 ms"

            is_ok = branch == "ok"
            pill_class = "status-pill-ok" if is_ok else "status-pill-error"
            pill_label = "OK" if is_ok else "ERROR"

            items_html.append(f"""
            <div class="worker-sub-row {'success-row' if is_ok else 'error-row'}">
                <div class="worker-tool-meta">
                    <span class="worker-tool-name">{_esc(w_name)} Worker</span>
                    <span class="{pill_class}">{pill_label}</span>
                </div>
                <div class="worker-details-text">Latency: {dur_str_sub} | {_esc(ws.get('output', ''))}</div>
            </div>
            """)

    return f"""
    <div class="timeline-item">
        <div class="timeline-dot" style="border-color: {COLOR_CODE_API};"></div>
        <div class="timeline-card workers-group-card">
            <div class="timeline-card-header">
                <div class="step-title-group">
                    <span class="step-title">Parallel Diagnostic Workers</span>
                    <span class="step-badge" style="background-color: {COLOR_CODE_API};">CONCURRENT GATHER</span>
                </div>
                <span class="step-duration">{dur_str} (concurrent)</span>
            </div>
            <div class="workers-list-box">
                {''.join(items_html)}
            </div>
        </div>
    </div>
    """


def _render_evaluator_loop_card(
    eval_steps: list[dict[str, Any]],
    eval_verdicts: list[dict[str, Any]] | None,
) -> str:
    # Build attempt sub-cards
    attempts_data: dict[int, dict[str, Any]] = {}

    # Read from trace
    for s in eval_steps:
        step_name = s.get("step", "")
        if "attempt_" in step_name and "troubleshooter" in step_name:
            try:
                num = int(step_name.split("_")[-1])
                attempts_data.setdefault(num, {})["draft"] = s.get("output", "")
                attempts_data[num]["troubleshooter_duration"] = s.get("duration_ms", 0.0)
            except Exception:
                pass
        elif "verdict_" in step_name:
            try:
                num = int(step_name.split("_")[-1])
                attempts_data.setdefault(num, {})["verdict_branch"] = s.get("branch", "")
                attempts_data[num]["verdict_output"] = s.get("output", "")
                attempts_data[num]["evaluator_duration"] = s.get("duration_ms", 0.0)
            except Exception:
                pass

    # Enrich from eval_verdicts if available
    for ev in (eval_verdicts or []):
        att_num = ev.get("attempt", 1)
        target = attempts_data.setdefault(att_num, {})
        target["approved"] = ev.get("approved", False)
        target["issues"] = ev.get("issues", [])
        target["critique"] = ev.get("critique", "")

    attempts_html = []
    for att_num in sorted(attempts_data):
        att = attempts_data[att_num]
        approved = att.get("approved", att.get("verdict_branch") == "approved")

        badge_html = (
            '<span class="eval-verdict-badge badge-approved">&#10003; APPROVED</span>'
            if approved
            else '<span class="eval-verdict-badge badge-rejected">&#10007; REJECTED</span>'
        )

        draft_text = att.get("draft", "")
        if draft_text.startswith("draft:"):
            draft_text = draft_text[6:].strip()

        issues = att.get("issues") or []
        critique = att.get("critique") or ""

        issues_html = ""
        if issues:
            issues_list = "".join(f"<li>{_esc(iss)}</li>" for iss in issues)
            issues_html = f"""
            <div class="eval-issues-box">
                <span class="eval-sub-label">Issues Detected ({len(issues)}):</span>
                <ul class="eval-issues-list">{issues_list}</ul>
            </div>
            """

        critique_html = ""
        if critique:
            critique_html = f"""
            <div class="eval-critique-box">
                <span class="eval-sub-label">Critique Feedback for Next Attempt:</span>
                <div class="eval-critique-text">{_esc(critique)}</div>
            </div>
            """

        attempts_html.append(f"""
        <div class="eval-attempt-box {'attempt-passed' if approved else 'attempt-failed'}">
            <div class="eval-attempt-header">
                <span class="eval-attempt-title">Attempt {att_num}</span>
                {badge_html}
            </div>
            <div class="eval-draft-box">
                <span class="eval-sub-label">Troubleshooter Draft Proposal:</span>
                <div class="eval-draft-text">{_esc(draft_text)}</div>
            </div>
            {issues_html}
            {critique_html}
        </div>
        """)

    return f"""
    <div class="timeline-item">
        <div class="timeline-dot" style="border-color: {COLOR_LLM_AGENT};"></div>
        <div class="timeline-card eval-loop-card">
            <div class="timeline-card-header">
                <div class="step-title-group">
                    <span class="step-title">Evaluator-Optimizer Loop</span>
                    <span class="step-badge" style="background-color: {COLOR_LLM_AGENT};">MAX 3 ATTEMPTS</span>
                </div>
                <span class="step-duration">{len(attempts_data)} attempt(s)</span>
            </div>
            <div class="eval-attempts-container">
                {''.join(attempts_html)}
            </div>
        </div>
    </div>
    """


def render_timeline(result: dict[str, Any] | None) -> str:
    """Renders the styled HTML vertical timeline for the last incident request."""
    if not result or not result.get("trace"):
        return """
        <div class="empty-trace-container">
            <div class="empty-trace-icon">&#9203;</div>
            <h3 class="empty-trace-title">No Live Flow Trace Available</h3>
            <p class="empty-trace-text">
                Send an incident message in <strong>Tab 1 (Employee Chat)</strong> or click one of the quick scenario buttons
                (C1 - C11) to view the complete pipeline execution timeline.
            </p>
        </div>
        """

    trace = result.get("trace", [])
    tool_results = result.get("tool_results", [])
    tool_errors = result.get("tool_errors", [])
    eval_verdicts = result.get("eval_verdicts", [])

    timeline_items: list[str] = []
    i = 0
    n = len(trace)

    while i < n:
        step = trace[i]
        step_name = step.get("step", "")

        # 1. Group consecutive parallel workers
        if step_name.startswith("worker_"):
            worker_steps = []
            while i < n and trace[i].get("step", "").startswith("worker_"):
                worker_steps.append(trace[i])
                i += 1
            timeline_items.append(_render_parallel_workers_card(worker_steps, tool_results, tool_errors))
            continue

        # 2. Group evaluator-optimizer loop
        if (
            step_name.startswith("troubleshooter_attempt_")
            or step_name.startswith("evaluator_verdict_")
            or step_name == "evaluator_loop"
        ):
            eval_steps = []
            while i < n and (
                trace[i].get("step", "").startswith("troubleshooter_attempt_")
                or trace[i].get("step", "").startswith("evaluator_verdict_")
                or trace[i].get("step") == "evaluator_loop"
            ):
                eval_steps.append(trace[i])
                i += 1
            timeline_items.append(_render_evaluator_loop_card(eval_steps, eval_verdicts))
            continue

        # 3. Standard step
        timeline_items.append(_render_standard_step(step))
        i += 1

    # Collapsible raw JSON
    json_str = json.dumps(result, indent=2, default=str)
    raw_json_html = f"""
    <details class="timeline-json-details">
        <summary class="timeline-json-summary">Raw Result JSON (Click to inspect)</summary>
        <div class="timeline-json-box">
            <pre><code>{_esc(json_str)}</code></pre>
        </div>
    </details>
    """

    return f"""
    <div class="trace-timeline-wrapper">
        <div class="timeline-header-info">
            <span class="trace-summary-title">Execution Pipeline Trace</span>
            <span class="trace-steps-count">{len(trace)} steps executed | Total Duration: {result.get('duration_ms', 0.0):.1f} ms</span>
        </div>
        <div class="timeline-container">
            {''.join(timeline_items)}
        </div>
        {raw_json_html}
    </div>
    """
