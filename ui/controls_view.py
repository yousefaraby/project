"""Controls and Fault Injection View helpers for Gradio UI Tab 5."""
from __future__ import annotations

import html
from typing import Any

from app.controls import (
    AGENT_SERVICE_FAULTS,
    TOOL_MODES,
    TOOL_NAMES,
    TROUBLESHOOTER_BEHAVIORS,
    controls,
)
from app.services.accessors import reset_all_data, reset_rate_limit, set_fault, set_kill_switch


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


def render_controls_status_html() -> str:
    """Renders a real-time status card showing the state of every runtime control."""
    # Kill switch styling
    if controls.kill_switch:
        ks_badge = '<span style="background: #dc2626; color: white; padding: 3px 10px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem;">ON (AGENT BLOCKED)</span>'
    else:
        ks_badge = '<span style="background: #16a34a; color: white; padding: 3px 10px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem;">OFF (NORMAL)</span>'

    # Agent fault styling
    af = controls.agent_service_fault
    if af == "none":
        af_badge = '<span style="background: #16a34a; color: white; padding: 3px 10px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem;">NONE (HEALTHY)</span>'
    else:
        af_badge = f'<span style="background: #dc2626; color: white; padding: 3px 10px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem;">{_esc(af.upper())} (WF-ERR)</span>'

    # Troubleshooter behavior styling
    tb = controls.troubleshooter_behavior or "ok"
    if tb == "ok":
        tb_badge = '<span style="background: #16a34a; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 0.78rem;">OK</span>'
    elif tb == "hallucinate_once":
        tb_badge = '<span style="background: #ca8a04; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 0.78rem;">HALLUCINATE ONCE</span>'
    else:
        tb_badge = '<span style="background: #dc2626; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 0.78rem;">HALLUCINATE ALWAYS</span>'

    # Tools badges
    tool_items = []
    for tool in TOOL_NAMES:
        mode = controls.tool_mode(tool)
        if mode == "ok":
            col = "#16a34a"
            bg = "#dcfce7"
        elif mode == "slow":
            col = "#b45309"
            bg = "#fef3c7"
        else:
            col = "#dc2626"
            bg = "#fee2e2"
        tool_items.append(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;">
            <code style="font-size: 0.82rem; color: #1e293b; font-weight: 600;">{_esc(tool)}</code>
            <span style="background: {bg}; color: {col}; padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75rem;">{mode.upper()}</span>
        </div>
        """)

    return f"""
    <div style="background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 16px;">
        <div style="font-weight: 700; font-size: 0.95rem; color: #0f172a; margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between;">
            <span>&#9881; LIVE RUNTIME FAULT INJECTION STATE</span>
            <span style="font-size: 0.75rem; color: #64748b; font-weight: normal;">(Updated dynamically on every control change)</span>
        </div>

        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 14px;">
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px;">
                <span style="display: block; font-size: 0.72rem; color: #64748b; font-weight: 700; margin-bottom: 4px;">EMERGENCY KILL SWITCH</span>
                {ks_badge}
            </div>
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px;">
                <span style="display: block; font-size: 0.72rem; color: #64748b; font-weight: 700; margin-bottom: 4px;">AGENT SERVICE FAULT</span>
                {af_badge}
            </div>
            <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px;">
                <span style="display: block; font-size: 0.72rem; color: #64748b; font-weight: 700; margin-bottom: 4px;">TROUBLESHOOTER BEHAVIOR</span>
                {tb_badge}
            </div>
        </div>

        <div style="font-size: 0.75rem; font-weight: 700; color: #475569; margin-bottom: 6px;">DIAGNOSTIC WORKER READ-ONLY TOOL MODES:</div>
        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px;">
            {''.join(tool_items)}
        </div>
    </div>
    """
