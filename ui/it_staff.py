"""IT Staff View helpers for Gradio UI Tab 3 (Tickets, Review Queue, Alerts, Outbox)."""
from __future__ import annotations

import html
from typing import Any

from app.services.accessors import (
    get_audit,
    get_ticket,
    list_alerts,
    list_outbox,
    list_review_queue,
    list_tickets,
)
from ui.theme import (
    COLOR_BLOCKED_FAILED,
    COLOR_CODE_API,
    COLOR_DECISION,
    COLOR_HUMAN_LOOP,
    COLOR_LLM_AGENT,
    COLOR_SUCCESS,
    OUTCOME_COLORS,
    OUTCOME_LABELS,
)


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


def get_tickets_table_data() -> list[list[str]]:
    """Fetches all tickets formatted for gr.DataFrame.

    Columns: ID, Employee, Status, Outcome, Flags, Severity, Created At
    """
    tickets = list_tickets()
    rows: list[list[str]] = []

    for t in sorted(tickets, key=lambda x: x.ticket_id, reverse=True):
        audits = get_audit(t.ticket_id)
        latest_audit = audits[-1] if audits else {}
        triage = latest_audit.get("triage") or {}

        # Flags (NEEDS-MANUAL, flagged, P1)
        flags: list[str] = []
        if (
            t.needs_manual
            or "NEEDS-MANUAL" in t.tags
            or "human-review" in t.tags
            or latest_audit.get("outcome") in ("escalated_to_human", "unresolved_handoff_L2")
        ):
            flags.append("NEEDS-MANUAL")
        if t.flagged or "guardrail-blocked" in t.tags or latest_audit.get("kw_flag") or triage.get("security_flag"):
            flags.append("flagged")
        effective_sev = triage.get("severity") or t.severity
        if t.severity in ("critical", "high") or effective_sev in ("critical", "high") or "P1" in t.tags:
            flags.append("P1")
        flags_str = ", ".join(flags) if flags else "-"

        # Outcome from audit log
        outcome = latest_audit.get("outcome", "-")
        outcome_str = OUTCOME_LABELS.get(outcome, outcome) if outcome != "-" else "-"

        rows.append([
            t.ticket_id,
            t.user_id,
            t.status.value,
            outcome_str,
            flags_str,
            effective_sev.upper(),
            t.created_at[:19].replace("T", " ") if t.created_at else "-",
        ])

    return rows


def render_ticket_detail(ticket_id: str | None) -> str:
    """Renders detailed HTML view for a selected ticket."""
    if not ticket_id:
        return """
        <div style="background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 24px; text-align: center; color: #64748b;">
            <span style="font-size: 1.5rem;">&#128221;</span>
            <div style="font-weight: 600; margin-top: 6px;">No Ticket Selected</div>
            <div style="font-size: 0.82rem;">Select a ticket row in the table above to view full conversation thread, internal technician notes, and history.</div>
        </div>
        """

    try:
        t = get_ticket(ticket_id)
    except Exception as exc:  # noqa: BLE001
        return f'<div style="color: #dc2626; padding: 12px;">Error loading ticket {ticket_id}: {_esc(exc)}</div>'

    status_color = "#16a34a" if "Resolved" in t.status.value or "Closed" in t.status.value else "#ea580c"

    # Format comments (employee-facing thread)
    comments_html = []
    if t.comments:
        for c in t.comments:
            author = c.get("author", "user")
            is_user = author == "user"
            align_bg = "#eff6ff" if is_user else "#f8fafc"
            align_border = "#bfdbfe" if is_user else "#e2e8f0"
            badge_label = "EMPLOYEE" if is_user else "IT DESK / AGENT"
            badge_col = COLOR_CODE_API if is_user else COLOR_LLM_AGENT

            comments_html.append(f"""
            <div style="background: {align_bg}; border: 1px solid {align_border}; border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-weight: 700; font-size: 0.80rem; color: {badge_col};">{badge_label}</span>
                    <span style="font-size: 0.72rem; color: #94a3b8;">{_esc(c.get('ts', ''))[:19].replace('T', ' ')}</span>
                </div>
                <div style="font-size: 0.85rem; color: #1e293b; white-space: pre-wrap;">{_esc(c.get('text', ''))}</div>
            </div>
            """)
    else:
        comments_html.append('<div style="color: #94a3b8; font-size: 0.82rem; font-style: italic;">No employee messages recorded on this ticket.</div>')

    # Format internal notes (technician-only)
    notes_html = []
    if t.internal_notes:
        for n in t.internal_notes:
            notes_html.append(f"""
            <div style="background: #fffbeb; border: 1px dashed #f59e0b; border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-weight: 700; font-size: 0.78rem; color: #b45309;">&#128274; INTERNAL TECHNICIAN NOTE (NOT VISIBLE TO USER)</span>
                    <span style="font-size: 0.72rem; color: #92400e;">{_esc(n.get('ts', ''))[:19].replace('T', ' ')}</span>
                </div>
                <div style="font-size: 0.82rem; color: #78350f; font-family: Consolas, monospace; white-space: pre-wrap;">{_esc(n.get('text', ''))}</div>
            </div>
            """)
    else:
        notes_html.append('<div style="color: #94a3b8; font-size: 0.82rem; font-style: italic;">No internal notes on this ticket.</div>')

    # Tags & Flags
    flags = []
    if t.needs_manual:
        flags.append('<span style="background: #fee2e2; color: #dc2626; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 0.72rem;">NEEDS-MANUAL</span>')
    if t.flagged:
        flags.append('<span style="background: #fee2e2; color: #dc2626; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 0.72rem;">FLAGGED</span>')
    for tag in t.tags:
        if tag not in ("NEEDS-MANUAL", "flagged"):
            flags.append(f'<span style="background: #f1f5f9; color: #475569; padding: 2px 6px; border-radius: 4px; font-weight: 600; font-size: 0.72rem;">{_esc(tag)}</span>')
    flags_html = " ".join(flags) if flags else '<span style="color: #94a3b8; font-size: 0.78rem;">None</span>'

    return f"""
    <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 12px;">
            <div>
                <span style="font-weight: 700; font-size: 1.15rem; color: #0f172a;">{_esc(t.ticket_id)}</span>
                <span style="font-size: 0.85rem; color: #64748b; margin-left: 8px;">Employee: <strong>{_esc(t.user_id)}</strong></span>
            </div>
            <span style="background: {status_color}; color: white; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.80rem;">{_esc(t.status.value)}</span>
        </div>

        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 14px; background: #f8fafc; border: 1px solid #edf2f7; border-radius: 6px; padding: 10px;">
            <div><span style="font-size: 0.72rem; color: #64748b; font-weight: 600; display: block;">SEVERITY</span><span style="font-weight: 700; font-size: 0.85rem;">{_esc(t.severity.upper())}</span></div>
            <div><span style="font-size: 0.72rem; color: #64748b; font-weight: 600; display: block;">ASSIGNEE</span><span style="font-weight: 600; font-size: 0.85rem;">{_esc(t.assignee or 'Unassigned')}</span></div>
            <div><span style="font-size: 0.72rem; color: #64748b; font-weight: 600; display: block;">FLAGS & TAGS</span><div>{flags_html}</div></div>
        </div>

        <div style="margin-bottom: 14px;">
            <span style="font-size: 0.75rem; color: #64748b; font-weight: 700; text-transform: uppercase;">Summary / Initial Issue:</span>
            <div style="font-size: 0.88rem; color: #0f172a; margin-top: 2px; font-weight: 500;">{_esc(t.summary)}</div>
        </div>

        <div style="margin-bottom: 16px;">
            <div style="font-weight: 700; font-size: 0.82rem; color: #334155; margin-bottom: 8px;">USER CONVERSATION THREAD:</div>
            {''.join(comments_html)}
        </div>

        <div>
            <div style="font-weight: 700; font-size: 0.82rem; color: #334155; margin-bottom: 8px;">TECHNICIAN & WORKFLOW INTERNAL NOTES:</div>
            {''.join(notes_html)}
        </div>
    </div>
    """


def render_human_review_queue_html() -> str:
    """Renders the Human Review Queue with prominent notice that draft was NOT sent to user."""
    queue = list_review_queue()

    if not queue:
        return """
        <div style="background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 24px; text-align: center; color: #64748b; margin-top: 10px;">
            <span style="font-size: 1.5rem;">&#9989;</span>
            <div style="font-weight: 600; margin-top: 6px;">Review Queue Empty</div>
            <div style="font-size: 0.82rem;">No incidents currently awaiting human review. Run C5 or C11 to test escalation.</div>
        </div>
        """

    cards = []
    for item in queue:
        tid = item.get("ticket_id", "n/a")
        uid = item.get("user_id", "n/a")
        draft = item.get("draft", "")
        reasons = item.get("escalation_reasons") or []
        evidence = item.get("evidence") or {}

        reasons_html = ", ".join(f"<code>{_esc(r)}</code>" for r in reasons) if reasons else "None specified"

        cards.append(f"""
        <div style="background: #ffffff; border: 2px solid #ea580c; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.06);">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #fed7aa; padding-bottom: 8px; margin-bottom: 10px;">
                <div>
                    <span style="font-weight: 700; font-size: 1.05rem; color: #9a3412;">Incident {_esc(tid)}</span>
                    <span style="font-size: 0.85rem; color: #475569; margin-left: 8px;">User: <strong>{_esc(uid)}</strong></span>
                </div>
                <span style="background: #ea580c; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem;">ESCALATED TO HUMAN</span>
            </div>

            <!-- MANDATORY PROMINENT NOTICE -->
            <div style="background: #fff7ed; border-left: 4px solid #ea580c; padding: 8px 12px; border-radius: 4px; margin-bottom: 12px;">
                <span style="font-weight: 700; font-size: 0.82rem; color: #9a3412;">&#9888; CRITICAL SAFETY ENFORCEMENT:</span>
                <span style="font-size: 0.82rem; color: #7c2d12; margin-left: 4px;">
                    This drafted resolution was <strong>NOT sent to the employee</strong>. The employee received only the pre-approved holding template.
                    Technician approval is strictly required before any action or communication.
                </span>
            </div>

            <div style="margin-bottom: 10px;">
                <span style="font-size: 0.75rem; font-weight: 700; color: #64748b; text-transform: uppercase;">Escalation Reasons:</span>
                <div style="font-size: 0.85rem; color: #b91c1c; margin-top: 2px;">{reasons_html}</div>
            </div>

            <div style="margin-bottom: 10px;">
                <span style="font-size: 0.75rem; font-weight: 700; color: #64748b; text-transform: uppercase;">Drafted Resolution Proposal (Internal Review Only):</span>
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; font-size: 0.85rem; color: #1e293b; margin-top: 4px; white-space: pre-wrap;">{_esc(draft or 'No draft generated')}</div>
            </div>

            <div>
                <span style="font-size: 0.75rem; font-weight: 700; color: #64748b; text-transform: uppercase;">Diagnostic Findings & Evidence:</span>
                <div style="background: #f1f5f9; border-radius: 4px; padding: 8px; font-family: Consolas, monospace; font-size: 0.78rem; color: #334155; margin-top: 4px; max-height: 120px; overflow-y: auto;">
                    {_esc(evidence)}
                </div>
            </div>
        </div>
        """)

    return "\n".join(cards)


def get_alerts_table_data() -> list[list[str]]:
    """Fetches all system alerts formatted for gr.DataFrame.

    Columns: Timestamp, Channel, Incident ID, Severity, Timing, Reason / Message
    """
    alerts = list_alerts()
    rows: list[list[str]] = []

    for a in sorted(alerts, key=lambda x: x.get("ts", ""), reverse=True):
        channel = a.get("channel", "n/a")
        sev = a.get("severity", "medium").upper()
        # Timing visibility: SOC alerts for critical incidents are timestamped before diagnostics
        timing = "PRE-DIAGNOSTIC" if channel == "SOC" or sev in ("HIGH", "CRITICAL") else "POST-DIAGNOSTIC"

        rows.append([
            a.get("ts", "")[:19].replace("T", " "),
            channel,
            a.get("incident_id", "n/a"),
            sev,
            timing,
            a.get("message", ""),
        ])

    return rows


def get_outbox_table_data() -> list[list[str]]:
    """Fetches all outbound messages delivered to employees.

    Columns: Timestamp, Ticket ID, User ID, Kind, Idempotency Key, Delivered Message
    """
    outbox = list_outbox()
    rows: list[list[str]] = []

    for o in sorted(outbox, key=lambda x: x.get("ts", ""), reverse=True):
        rows.append([
            o.get("ts", "")[:19].replace("T", " "),
            o.get("ticket_id", "n/a"),
            o.get("user_id", "n/a"),
            o.get("kind", "reply"),
            o.get("idempotency_key", "-"),
            o.get("text", ""),
        ])

    return rows
