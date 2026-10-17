"""UI theme, color palette, and styling for Gradio UI."""
from __future__ import annotations

import gradio as gr

# Core color codes (reused everywhere across the application)
COLOR_CODE_API = "#2563eb"        # Blue
COLOR_LLM_AGENT = "#9333ea"       # Purple
COLOR_DECISION = "#ca8a04"        # Yellow / amber for high contrast
COLOR_SUCCESS = "#16a34a"         # Green
COLOR_HUMAN_LOOP = "#ea580c"      # Orange
COLOR_BLOCKED_FAILED = "#dc2626"  # Red

OUTCOME_COLORS: dict[str, str] = {
    "auto_resolved": COLOR_SUCCESS,
    "needs_more_info": COLOR_DECISION,
    "escalated_to_human": COLOR_HUMAN_LOOP,
    "unresolved_handoff_L2": COLOR_HUMAN_LOOP,
    "blocked_by_guardrail": COLOR_BLOCKED_FAILED,
    "action_failed": COLOR_BLOCKED_FAILED,
    "system_error": COLOR_BLOCKED_FAILED,
    "unauthorized": COLOR_BLOCKED_FAILED,
    "rate_limited": COLOR_BLOCKED_FAILED,
    "kill_switch": COLOR_HUMAN_LOOP,
}

OUTCOME_LABELS: dict[str, str] = {
    "auto_resolved": "AUTO RESOLVED",
    "needs_more_info": "NEEDS MORE INFO",
    "escalated_to_human": "ESCALATED TO HUMAN",
    "unresolved_handoff_L2": "UNRESOLVED HANDOFF L2",
    "blocked_by_guardrail": "BLOCKED BY GUARDRAIL",
    "action_failed": "ACTION FAILED",
    "system_error": "SYSTEM ERROR (WF-ERR)",
    "unauthorized": "401 UNAUTHORIZED",
    "rate_limited": "429 RATE LIMITED",
    "kill_switch": "KILL SWITCH ACTIVATED",
}

CUSTOM_CSS = """
:root {
    --color-code-api: #2563eb;
    --color-llm-agent: #9333ea;
    --color-decision: #ca8a04;
    --color-success: #16a34a;
    --color-human-loop: #ea580c;
    --color-blocked-failed: #dc2626;
}

/* Header styles */
.app-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 20px;
    background: #0f172a;
    color: #f8fafc;
    border-radius: 10px;
    margin-bottom: 16px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
}

.app-title-group {
    display: flex;
    flex-direction: column;
}

.app-title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #ffffff;
    margin: 0;
    letter-spacing: -0.02em;
}

.app-subtitle {
    font-size: 0.85rem;
    color: #94a3b8;
    margin-top: 2px;
}

.mock-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #fef3c7;
    color: #92400e;
    border: 1px solid #f59e0b;
    padding: 6px 14px;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    text-transform: uppercase;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

.mock-badge-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: #d97706;
}

/* Status Card */
.status-card-box {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 16px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04);
}

.status-card-box.dark {
    background: #1e293b;
    border-color: #334155;
    color: #f8fafc;
}

.status-card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 10px;
    margin-bottom: 12px;
}

.status-card-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #1e293b;
    margin: 0;
}

.badge-outcome {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    color: #ffffff;
    font-size: 0.78rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.02em;
}

.status-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin-bottom: 12px;
}

.status-item {
    background: #f8fafc;
    border: 1px solid #edf2f7;
    border-radius: 6px;
    padding: 8px 10px;
}

.status-label {
    display: block;
    font-size: 0.72rem;
    text-transform: uppercase;
    color: #64748b;
    font-weight: 600;
    letter-spacing: 0.02em;
    margin-bottom: 2px;
}

.status-val {
    font-size: 0.88rem;
    font-weight: 600;
    color: #0f172a;
    word-break: break-all;
}

.status-full-row {
    background: #f8fafc;
    border: 1px solid #edf2f7;
    border-radius: 6px;
    padding: 8px 10px;
    margin-bottom: 8px;
}

.badge-security-yes {
    background-color: #dc2626;
    color: white;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
}

.badge-security-no {
    background-color: #e2e8f0;
    color: #475569;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
}

/* Legend bar */
.color-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    font-size: 0.75rem;
    margin-top: 10px;
    padding: 8px;
    background: #f1f5f9;
    border-radius: 6px;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 4px;
    font-weight: 500;
}

.legend-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    display: inline-block;
}

/* Scenario button bar */
.scenario-button-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 8px;
}

.tab-placeholder {
    padding: 40px;
    text-align: center;
    background: #f8fafc;
    border: 2px dashed #cbd5e1;
    border-radius: 12px;
    margin-top: 16px;
}

.tab-placeholder h3 {
    color: #334155;
    margin-bottom: 8px;
}

.tab-placeholder p {
    color: #64748b;
    font-size: 0.95rem;
}

/* Timeline Styles */
.trace-timeline-wrapper {
    padding: 10px 4px;
}

.timeline-header-info {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 20px;
}

.trace-summary-title {
    font-weight: 700;
    color: #0f172a;
    font-size: 1.05rem;
}

.trace-steps-count {
    font-size: 0.85rem;
    color: #475569;
    font-weight: 600;
}

.timeline-container {
    position: relative;
    padding-left: 28px;
    margin-top: 10px;
}

.timeline-container::before {
    content: "";
    position: absolute;
    left: 8px;
    top: 10px;
    bottom: 10px;
    width: 2px;
    background: #cbd5e1;
}

.timeline-item {
    position: relative;
    margin-bottom: 16px;
}

.timeline-dot {
    position: absolute;
    left: -28px;
    top: 12px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #ffffff;
    border: 3px solid #64748b;
    box-shadow: 0 0 0 2px #f8fafc;
    z-index: 2;
}

.timeline-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px 16px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}

.timeline-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.step-title-group {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
}

.step-title {
    font-weight: 700;
    font-size: 0.95rem;
    color: #0f172a;
}

.step-badge {
    font-size: 0.70rem;
    font-weight: 700;
    color: #ffffff;
    padding: 2px 8px;
    border-radius: 4px;
    letter-spacing: 0.03em;
}

.step-duration {
    font-size: 0.78rem;
    color: #64748b;
    font-weight: 600;
    font-family: Consolas, monospace;
}

.decision-branch {
    font-size: 0.75rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 9999px;
}

.branch-yes {
    background: #dcfce7;
    color: #15803d;
    border: 1px solid #86efac;
}

.branch-no {
    background: #fee2e2;
    color: #b91c1c;
    border: 1px solid #fca5a5;
}

.branch-warn {
    background: #fef3c7;
    color: #b45309;
    border: 1px solid #fde68a;
}

.branch-info {
    background: #e0f2fe;
    color: #0369a1;
    border: 1px solid #bae6fd;
}

.step-io-grid {
    background: #f8fafc;
    border: 1px solid #f1f5f9;
    border-radius: 6px;
    padding: 8px 10px;
    margin-top: 6px;
}

.step-io-row {
    display: flex;
    gap: 8px;
    font-size: 0.82rem;
    margin-bottom: 4px;
}

.step-io-row:last-child {
    margin-bottom: 0;
}

.step-io-tag {
    font-size: 0.68rem;
    font-weight: 700;
    color: #64748b;
    background: #e2e8f0;
    padding: 1px 6px;
    border-radius: 3px;
    min-width: 50px;
    text-align: center;
    line-height: 1.4;
    height: fit-content;
}

.step-io-content {
    color: #334155;
    word-break: break-all;
    font-family: Consolas, monospace;
    font-size: 0.80rem;
}

/* Workers Group */
.workers-group-card {
    background: #f8fafc;
    border-left: 4px solid var(--color-code-api);
}

.workers-list-box {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 8px;
}

.worker-sub-row {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 8px 12px;
}

.worker-sub-row.error-row {
    border-color: #fecaca;
    background: #fffbfb;
}

.worker-tool-meta {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
}

.worker-tool-name {
    font-weight: 700;
    font-size: 0.88rem;
    color: #1e293b;
    font-family: Consolas, monospace;
}

.worker-details-text {
    font-size: 0.80rem;
    color: #64748b;
}

.status-pill-ok {
    background: #dcfce7;
    color: #166534;
    font-weight: 700;
    font-size: 0.72rem;
    padding: 2px 8px;
    border-radius: 4px;
}

.status-pill-error {
    background: #fee2e2;
    color: #991b1b;
    font-weight: 700;
    font-size: 0.72rem;
    padding: 2px 8px;
    border-radius: 4px;
}

.status-pill-timeout {
    background: #ffedd5;
    color: #9a3412;
    font-weight: 700;
    font-size: 0.72rem;
    padding: 2px 8px;
    border-radius: 4px;
}

/* Evaluator Loop */
.eval-loop-card {
    background: #faf5ff;
    border-left: 4px solid var(--color-llm-agent);
}

.eval-attempts-container {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-top: 10px;
}

.eval-attempt-box {
    background: #ffffff;
    border: 1px solid #e9d5ff;
    border-radius: 6px;
    padding: 10px 14px;
}

.eval-attempt-box.attempt-passed {
    border-color: #bbf7d0;
}

.eval-attempt-box.attempt-failed {
    border-color: #fecaca;
}

.eval-attempt-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid #f1f5f9;
}

.eval-attempt-title {
    font-weight: 700;
    font-size: 0.90rem;
    color: #3b0764;
}

.eval-verdict-badge {
    font-size: 0.75rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
}

.badge-approved {
    background: #16a34a;
    color: #ffffff;
}

.badge-rejected {
    background: #dc2626;
    color: #ffffff;
}

.eval-sub-label {
    display: block;
    font-size: 0.72rem;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    margin-bottom: 3px;
}

.eval-draft-text {
    font-size: 0.82rem;
    color: #1e293b;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    padding: 6px 10px;
    border-radius: 4px;
    word-break: break-word;
}

.eval-issues-box {
    margin-top: 8px;
}

.eval-issues-list {
    margin: 4px 0 0 16px;
    padding: 0;
    font-size: 0.80rem;
    color: #b91c1c;
}

.eval-critique-box {
    margin-top: 8px;
    background: #fef2f2;
    border: 1px dashed #f87171;
    border-radius: 4px;
    padding: 6px 10px;
}

.eval-critique-text {
    font-size: 0.80rem;
    color: #991b1b;
}

/* Raw JSON Accordion */
.timeline-json-details {
    margin-top: 24px;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background: #ffffff;
    overflow: hidden;
}

.timeline-json-summary {
    padding: 10px 16px;
    font-weight: 600;
    font-size: 0.90rem;
    cursor: pointer;
    background: #f1f5f9;
    color: #334155;
    outline: none;
}

.timeline-json-box {
    padding: 12px 16px;
    background: #0f172a;
    color: #38bdf8;
    max-height: 420px;
    overflow-y: auto;
}

.timeline-json-box pre {
    margin: 0;
    font-family: Consolas, monospace;
    font-size: 0.80rem;
    white-space: pre-wrap;
    word-break: break-all;
}

/* Empty State */
.empty-trace-container {
    padding: 48px 24px;
    text-align: center;
    background: #f8fafc;
    border: 2px dashed #cbd5e1;
    border-radius: 12px;
    margin: 20px 0;
}

.empty-trace-icon {
    font-size: 2.5rem;
    margin-bottom: 12px;
}

.empty-trace-title {
    color: #1e293b;
    font-size: 1.15rem;
    font-weight: 700;
    margin: 0 0 8px 0;
}

.empty-trace-text {
    color: #64748b;
    font-size: 0.90rem;
    max-width: 500px;
    margin: 0 auto;
}
"""


def create_theme() -> gr.Theme:
    """Creates a custom Gradio theme using only offline system fonts (no Google/CDN fonts)."""
    return gr.themes.Soft(
        primary_hue=gr.themes.colors.blue,
        secondary_hue=gr.themes.colors.purple,
        neutral_hue=gr.themes.colors.slate,
        font=[
            gr.themes.Font("Segoe UI"),
            gr.themes.Font("Helvetica Neue"),
            gr.themes.Font("Arial"),
            gr.themes.Font("sans-serif"),
        ],
        font_mono=[
            gr.themes.Font("Consolas"),
            gr.themes.Font("Courier New"),
            gr.themes.Font("monospace"),
        ],
    )


def render_status_card(result: dict | None = None) -> str:
    """Renders the HTML status card beside the chat for the last incident request."""
    if not result:
        return """
        <div class="status-card-box">
            <div class="status-card-header">
                <span class="status-card-title">Incident Status</span>
                <span class="badge-outcome" style="background-color: #64748b;">IDLE</span>
            </div>
            <p style="color: #64748b; font-size: 0.88rem; margin: 0; padding: 12px 0;">
                No active request in current session. Select an employee and submit a message or click a scenario below.
            </p>
        </div>
        """

    outcome = result.get("outcome") or ("unauthorized" if result.get("status") == 401 else "unknown")
    badge_color = OUTCOME_COLORS.get(outcome, "#64748b")
    badge_text = OUTCOME_LABELS.get(outcome, outcome.replace("_", " ").upper())

    ticket_id = result.get("ticket_id") or "None"
    ticket_status = result.get("ticket_status") or ("Created" if ticket_id != "None" else "No ticket")
    category = result.get("category") or "n/a"
    severity = result.get("severity") or "n/a"
    sec_flag = result.get("security_flag")
    sec_badge = (
        '<span class="badge-security-yes">FLAGGED</span>'
        if sec_flag
        else '<span class="badge-security-no">NO</span>'
    )

    eval_attempts = result.get("eval_attempts", 0)
    duration_ms = result.get("duration_ms", 0.0)
    duration_str = f"{duration_ms:.1f} ms" if duration_ms else "n/a"

    escalations = result.get("escalation_reasons") or []
    if isinstance(escalations, list):
        escalation_str = ", ".join(str(e) for e in escalations) if escalations else "None"
    else:
        escalation_str = str(escalations)

    return f"""
    <div class="status-card-box">
        <div class="status-card-header">
            <span class="status-card-title">Incident Status</span>
            <span class="badge-outcome" style="background-color: {badge_color};">{badge_text}</span>
        </div>
        <div class="status-grid">
            <div class="status-item">
                <span class="status-label">Ticket ID</span>
                <span class="status-val">{ticket_id}</span>
            </div>
            <div class="status-item">
                <span class="status-label">Ticket Status</span>
                <span class="status-val">{ticket_status}</span>
            </div>
            <div class="status-item">
                <span class="status-label">Category</span>
                <span class="status-val">{category}</span>
            </div>
            <div class="status-item">
                <span class="status-label">Severity</span>
                <span class="status-val">{severity}</span>
            </div>
            <div class="status-item">
                <span class="status-label">Security Flag</span>
                <span class="status-val">{sec_badge}</span>
            </div>
            <div class="status-item">
                <span class="status-label">Evaluator Attempts</span>
                <span class="status-val">{eval_attempts}</span>
            </div>
            <div class="status-item" style="grid-column: span 2;">
                <span class="status-label">Duration</span>
                <span class="status-val">{duration_str}</span>
            </div>
        </div>
        <div class="status-full-row">
            <span class="status-label">Escalation Reasons</span>
            <span class="status-val" style="font-size: 0.82rem; font-weight: normal; color: #334155;">{escalation_str}</span>
        </div>
        <div class="color-legend">
            <span class="legend-item"><span class="legend-dot" style="background: {COLOR_CODE_API}"></span>Code/API</span>
            <span class="legend-item"><span class="legend-dot" style="background: {COLOR_LLM_AGENT}"></span>LLM Agent</span>
            <span class="legend-item"><span class="legend-dot" style="background: {COLOR_DECISION}"></span>Decision</span>
            <span class="legend-item"><span class="legend-dot" style="background: {COLOR_SUCCESS}"></span>Success</span>
            <span class="legend-item"><span class="legend-dot" style="background: {COLOR_HUMAN_LOOP}"></span>Human Review</span>
            <span class="legend-item"><span class="legend-dot" style="background: {COLOR_BLOCKED_FAILED}"></span>Blocked/Failed</span>
        </div>
    </div>
    """
