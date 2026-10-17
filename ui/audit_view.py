"""Audit Log view helpers for Gradio UI Tab 4."""
from __future__ import annotations

import html
import json
from typing import Any

from app.services.accessors import get_audit_by_id, list_audit_records
from ui.theme import OUTCOME_COLORS, OUTCOME_LABELS


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


def get_audit_table_data(
    outcome: str = "All",
    user: str = "All",
    date_filter: str = "",
    sec_flag: str = "All",
) -> list[list[str]]:
    """Returns filtered audit records formatted for gr.DataFrame.

    Columns: ID, Timestamp, Incident ID, User ID, Outcome, Sec Flag, Reply Sent, Duration (ms)
    """
    records = list_audit_records(limit=250)
    rows: list[list[str]] = []

    for r in records:
        r_outcome = r.get("outcome", "")
        r_user = r.get("user_id", "")
        r_ts = r.get("timestamp", "")
        r_flag = bool(r.get("kw_flag", False))
        r_id = str(r.get("id", ""))
        r_inc = r.get("incident_id") or "-"

        # Filter by outcome
        if outcome != "All" and r_outcome != outcome:
            continue

        # Filter by user
        if user != "All" and r_user != user:
            continue

        # Filter by date substring (e.g. '2026-10-17' or '2026')
        if date_filter.strip() and date_filter.strip().lower() not in r_ts.lower():
            continue

        # Filter by security flag
        if sec_flag == "Flagged" and not r_flag:
            continue
        if sec_flag == "Unflagged" and r_flag:
            continue

        duration = f"{float(r.get('duration_ms', 0.0)):.1f}"
        reply_sent = "YES" if r.get("reply_sent") else "NO"
        outcome_label = OUTCOME_LABELS.get(r_outcome, r_outcome)
        sec_label = "FLAGGED" if r_flag else "-"

        rows.append([
            r_id,
            r_ts[:19].replace("T", " "),
            r_inc,
            r_user,
            outcome_label,
            sec_label,
            reply_sent,
            duration,
        ])

    return rows


def render_audit_detail(record_id: int | str | None) -> str:
    """Renders formatted JSON for an audit record with prominent [REDACTED] markers."""
    if not record_id or str(record_id).strip() == "":
        return """
        <div style="background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 24px; text-align: center; color: #64748b;">
            <span style="font-size: 1.5rem;">&#128269;</span>
            <div style="font-weight: 600; margin-top: 6px;">No Audit Record Selected</div>
            <div style="font-size: 0.82rem;">Click any row in the audit log table above to inspect its full immutable JSON record and secret redactions.</div>
        </div>
        """

    try:
        rid = int(str(record_id).strip())
        rec = get_audit_by_id(rid)
    except Exception as exc:  # noqa: BLE001
        return f'<div style="color: #dc2626; padding: 12px;">Error reading audit record {record_id}: {_esc(exc)}</div>'

    if not rec:
        return f'<div style="color: #64748b; padding: 12px;">Audit record #{record_id} not found.</div>'

    # Check for secrets redaction in record
    rec_json_str = json.dumps(rec, indent=2, ensure_ascii=False, default=str)
    has_redactions = "[REDACTED]" in rec_json_str

    if has_redactions:
        redaction_banner = """
        <div style="background: #fef2f2; border: 1px solid #ef4444; border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 1.3rem;">&#128272;</span>
            <div>
                <div style="font-weight: 700; color: #991b1b; font-size: 0.85rem;">SECRET REDACTION VERIFIED</div>
                <div style="font-size: 0.78rem; color: #7f1d1d;">
                    Sensitive credentials (passwords, tokens, or OTP codes) were stripped by the defense-in-depth redactor prior to database storage and replaced with <code>[REDACTED]</code>.
                </div>
            </div>
        </div>
        """
    else:
        redaction_banner = """
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; color: #475569; font-size: 0.80rem;">
            No sensitive credentials or secret patterns detected in this event message.
        </div>
        """

    # Escape HTML of JSON and highlight [REDACTED]
    escaped_json = html.escape(rec_json_str)
    highlighted_json = escaped_json.replace(
        "[REDACTED]",
        '<span style="background: #dc2626; color: #ffffff; padding: 2px 6px; border-radius: 3px; font-weight: bold; border: 1px solid #991b1b;">&#128274; [REDACTED]</span>'
    )

    r_outcome = rec.get("outcome", "-")
    badge_col = OUTCOME_COLORS.get(r_outcome, "#475569")
    outcome_label = OUTCOME_LABELS.get(r_outcome, r_outcome)

    return f"""
    <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 10px; margin-bottom: 12px;">
            <div>
                <span style="font-weight: 700; font-size: 1.1rem; color: #0f172a;">Audit Record #{rec.get('id', '')}</span>
                <span style="font-size: 0.85rem; color: #64748b; margin-left: 8px;">Incident: <strong>{_esc(rec.get('incident_id') or 'None')}</strong></span>
                <span style="font-size: 0.85rem; color: #64748b; margin-left: 8px;">User: <strong>{_esc(rec.get('user_id'))}</strong></span>
            </div>
            <span style="background: {badge_col}; color: white; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.80rem;">{outcome_label}</span>
        </div>

        {redaction_banner}

        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 12px; background: #f8fafc; border: 1px solid #edf2f7; border-radius: 6px; padding: 10px; font-size: 0.80rem;">
            <div><span style="color: #64748b; display: block; font-size: 0.72rem; font-weight: 600;">TIMESTAMP</span><strong>{_esc(rec.get('timestamp', ''))[:19].replace('T', ' ')}</strong></div>
            <div><span style="color: #64748b; display: block; font-size: 0.72rem; font-weight: 600;">KEYWORD FLAG</span><strong>{'YES' if rec.get('kw_flag') else 'NO'}</strong></div>
            <div><span style="color: #64748b; display: block; font-size: 0.72rem; font-weight: 600;">REPLY DELIVERED</span><strong>{'YES' if rec.get('reply_sent') else 'NO'}</strong></div>
            <div><span style="color: #64748b; display: block; font-size: 0.72rem; font-weight: 600;">DURATION</span><strong>{float(rec.get('duration_ms', 0)):.1f} ms</strong></div>
        </div>

        <div style="font-weight: 700; font-size: 0.80rem; color: #334155; margin-bottom: 6px;">RAW AUDIT JSON RECORD:</div>
        <pre style="background: #0f172a; color: #f1f5f9; padding: 14px; border-radius: 6px; overflow-x: auto; max-height: 480px; font-size: 0.78rem; font-family: Consolas, monospace; line-height: 1.45; border: 1px solid #1e293b;">{highlighted_json}</pre>
    </div>
    """
