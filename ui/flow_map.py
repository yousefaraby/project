"""Interactive visual flow map renderer for Gradio UI Tab 2 (Inline SVG).

Renders the end-to-end incident response pipeline graph:
- Backend gateway steps & Agent service steps
- Decisions (diamond indicators & branches)
- Parallel diagnostic workers group with per-tool status
- Evaluator-optimizer loop with per-attempt verdict badges
- The six outcome boxes, highlighting the final outcome
- Visited nodes and active edges highlighted; skipped nodes greyed out
- Resilient mapping driven from trace step names
"""
from __future__ import annotations

import html
from typing import Any

from ui.theme import (
    COLOR_BLOCKED_FAILED,
    COLOR_CODE_API,
    COLOR_DECISION,
    COLOR_HUMAN_LOOP,
    COLOR_LLM_AGENT,
    COLOR_SUCCESS,
)

# Trace step name to Graph Node ID mapping
TRACE_TO_NODE_MAP: dict[str, str] = {
    "receive_request": "receive_request",
    "auth": "auth",
    "rate_limit": "rate_limit",
    "kill_switch": "kill_switch",
    "load_session": "ticket",
    "ticket": "ticket",
    "agent_call": "agent_call",
    "validate_response": "agent_call",
    "input_guardrail": "input_guardrail",
    "keyword_scan": "keyword_scan",
    "triage": "triage",
    "missing_info_check": "missing_info_check",
    "routing_rules": "routing_rules",
    "immediate_alert": "immediate_alert",
    "plan": "plan",
    "worker_Network": "parallel_workers",
    "worker_Device": "parallel_workers",
    "worker_KB": "parallel_workers",
    "worker_Account": "parallel_workers",
    "aggregate_evidence": "aggregate_evidence",
    "evidence_check": "aggregate_evidence",
    "hard_rule_override": "routing_rules",
    "troubleshooter_attempt_1": "evaluator_loop",
    "evaluator_verdict_1": "evaluator_loop",
    "troubleshooter_attempt_2": "evaluator_loop",
    "evaluator_verdict_2": "evaluator_loop",
    "troubleshooter_attempt_3": "evaluator_loop",
    "evaluator_verdict_3": "evaluator_loop",
    "evaluator_loop": "evaluator_loop",
    "action_tools": "evaluator_loop",
    "outcome_auto_resolved": "outcome_auto_resolved",
    "outcome_needs_more_info": "outcome_needs_more_info",
    "outcome_escalated_to_human": "outcome_escalated_to_human",
    "outcome_unresolved_handoff_L2": "outcome_unresolved_handoff_L2",
    "outcome_blocked_by_guardrail": "outcome_blocked_by_guardrail",
    "outcome_action_failed": "outcome_system_error",
    "WF-ERR": "outcome_system_error",
    "write_audit": "write_audit",
    "update_session": "update_session",
}

OUTCOME_TO_NODE: dict[str, str] = {
    "auto_resolved": "outcome_auto_resolved",
    "needs_more_info": "outcome_needs_more_info",
    "escalated_to_human": "outcome_escalated_to_human",
    "unresolved_handoff_L2": "outcome_unresolved_handoff_L2",
    "blocked_by_guardrail": "outcome_blocked_by_guardrail",
    "system_error": "outcome_system_error",
    "action_failed": "outcome_system_error",
}

STANDARD_TOOLS: list[tuple[str, str]] = [
    ("check_vpn_status", "check_vpn_status"),
    ("check_network_status", "check_network_status"),
    ("check_device_status", "check_device_status"),
    ("check_account_status", "check_account_status"),
    ("search_it_knowledge", "search_it_knowledge"),
]


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


def _extract_visited(result: dict[str, Any] | None) -> tuple[set[str], list[str], str | None]:
    if not result:
        return set(), [], None

    trace = result.get("trace") or []
    visited_set: set[str] = set()
    visited_seq: list[str] = []

    for entry in trace:
        step = entry.get("step", "")
        node_id = TRACE_TO_NODE_MAP.get(step)
        if node_id:
            visited_set.add(node_id)
            if not visited_seq or visited_seq[-1] != node_id:
                visited_seq.append(node_id)

    outcome = result.get("outcome")
    outcome_node = OUTCOME_TO_NODE.get(outcome) if outcome else None

    if outcome_node:
        visited_set.add(outcome_node)
        if not visited_seq or visited_seq[-1] != outcome_node:
            visited_seq.append(outcome_node)

    return visited_set, visited_seq, outcome_node


def render_flow_map(result: dict[str, Any] | None = None) -> str:
    """Renders the complete SVG flow map with visited highlights and tool/attempt status."""
    visited_set, visited_seq, final_outcome_node = _extract_visited(result)
    is_idle = len(visited_set) == 0

    tool_results = (result or {}).get("tool_results") or []
    tool_errors = (result or {}).get("tool_errors") or []
    eval_verdicts = (result or {}).get("eval_verdicts") or []

    # Map tool status
    tool_status_map: dict[str, tuple[str, str, str]] = {}
    success_tools = {r.get("tool"): r for r in tool_results}
    error_tools = {e.get("tool"): e for e in tool_errors}

    workers_visited = "parallel_workers" in visited_set

    for tool_id, label in STANDARD_TOOLS:
        if not workers_visited:
            tool_status_map[tool_id] = ("SKIP", "#f1f5f9", "#94a3b8")
        elif tool_id in error_tools:
            err = error_tools[tool_id]
            is_timeout = "timeout" in err.get("error_type", "").lower()
            text = "TIMEOUT" if is_timeout else "ERROR"
            tool_status_map[tool_id] = (text, "#fee2e2", "#dc2626")
        elif tool_id in success_tools:
            tool_status_map[tool_id] = ("OK", "#dcfce7", "#16a34a")
        else:
            tool_status_map[tool_id] = ("-", "#f8fafc", "#94a3b8")

    # Evaluator loop status
    eval_visited = "evaluator_loop" in visited_set
    attempts_status: list[tuple[str, str, str]] = []

    if not eval_visited:
        attempts_status = [
            ("SKIP", "#f1f5f9", "#94a3b8"),
            ("SKIP", "#f1f5f9", "#94a3b8"),
            ("SKIP", "#f1f5f9", "#94a3b8"),
        ]
    else:
        for att_idx in range(1, 4):
            verd = next((v for v in eval_verdicts if v.get("attempt") == att_idx), None)
            if verd is not None:
                if verd.get("approved"):
                    attempts_status.append(("APPROVED", "#dcfce7", "#16a34a"))
                else:
                    attempts_status.append(("REJECTED", "#fee2e2", "#dc2626"))
            else:
                if att_idx == 1 and not eval_verdicts:
                    # Single approved attempt fallback
                    attempts_status.append(("APPROVED", "#dcfce7", "#16a34a"))
                else:
                    attempts_status.append(("-", "#f8fafc", "#94a3b8"))

    # Active edges set
    active_edge_pairs = set()
    for i in range(len(visited_seq) - 1):
        active_edge_pairs.add((visited_seq[i], visited_seq[i + 1]))

    # SVG Definitions
    svg_parts = [
        '<div class="flow-map-container" style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 16px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); overflow-x: auto;">',
        '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">',
        '  <span style="font-weight: 700; color: #0f172a; font-size: 0.98rem; display: flex; align-items: center; gap: 8px;">',
        '    <span>&#128506;</span> Interactive Architecture Flow Map',
        '  </span>',
        f'  <span style="font-size: 0.78rem; font-weight: 600; color: #64748b; background: #f1f5f9; padding: 3px 10px; border-radius: 9999px;">{"IDLE - Send message to trace" if is_idle else f"TRACE: {len(visited_set)} nodes visited"}</span>',
        '</div>',
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 520" width="100%" height="auto" style="font-family: Segoe UI, -apple-system, sans-serif;">',
        '<defs>',
        '  <marker id="arr-active" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 9 5 L 0 9 z" fill="#2563eb" />',
        '  </marker>',
        '  <marker id="arr-inactive" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">',
        '    <path d="M 0 1 L 9 5 L 0 9 z" fill="#cbd5e1" />',
        '  </marker>',
        '  <filter id="glow-outcome" x="-20%" y="-20%" width="140%" height="140%">',
        '    <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#16a34a" flood-opacity="0.35"/>',
        '  </filter>',
        '</defs>',
    ]

    # Stage background columns
    stages = [
        (20, 230, "STAGE 1: BACKEND GATEWAY", "#f8fafc", "#e2e8f0"),
        (280, 230, "STAGE 2: TRIAGE & ROUTING", "#f8fafc", "#e2e8f0"),
        (540, 270, "STAGE 3: DIAGNOSTICS & EVALUATOR", "#f8fafc", "#e2e8f0"),
        (840, 220, "STAGE 4: SIX OUTCOMES", "#f8fafc", "#e2e8f0"),
    ]

    for sx, sw, title, bg, border in stages:
        svg_parts.append(
            f'<rect x="{sx}" y="12" width="{sw}" height="440" rx="8" fill="{bg}" stroke="{border}" stroke-width="1"/>'
            f'<rect x="{sx}" y="12" width="{sw}" height="28" rx="8" fill="#e2e8f0"/>'
            f'<text x="{sx + sw//2}" y="31" fill="#475569" font-size="11" font-weight="700" text-anchor="middle" letter-spacing="0.5">{title}</text>'
        )

    # Predefined connection edges: (source, target, path_d)
    edges = [
        ("receive_request", "auth", "M 135 88 L 135 106"),
        ("auth", "rate_limit", "M 135 144 L 135 162"),
        ("rate_limit", "kill_switch", "M 135 200 L 135 218"),
        ("kill_switch", "ticket", "M 135 256 L 135 274"),
        ("ticket", "agent_call", "M 135 312 L 135 330"),
        ("agent_call", "input_guardrail", "M 230 349 C 260 349 260 69 300 69"),
        ("agent_call", "outcome_system_error", "M 230 355 C 260 360 810 370 855 341"),
        ("input_guardrail", "keyword_scan", "M 395 88 L 395 106"),
        ("input_guardrail", "outcome_blocked_by_guardrail", "M 490 69 C 520 69 810 270 855 287"),
        ("keyword_scan", "triage", "M 395 144 L 395 162"),
        ("triage", "missing_info_check", "M 395 200 L 395 218"),
        ("missing_info_check", "routing_rules", "M 395 256 L 395 274"),
        ("missing_info_check", "outcome_needs_more_info", "M 490 237 C 520 237 810 130 855 125"),
        ("routing_rules", "immediate_alert", "M 395 312 L 395 330"),
        ("routing_rules", "plan", "M 490 293 C 520 293 520 69 555 69"),
        ("immediate_alert", "plan", "M 490 349 C 530 349 530 80 555 75"),
        ("immediate_alert", "outcome_escalated_to_human", "M 490 349 C 530 349 810 180 855 179"),
        ("plan", "parallel_workers", "M 675 88 L 675 102"),
        ("parallel_workers", "aggregate_evidence", "M 675 237 L 675 248"),
        ("aggregate_evidence", "evaluator_loop", "M 675 284 L 675 296"),
        ("aggregate_evidence", "outcome_unresolved_handoff_L2", "M 795 266 C 815 266 825 233 855 233"),
        ("aggregate_evidence", "outcome_escalated_to_human", "M 795 266 C 815 266 825 179 855 179"),
        ("evaluator_loop", "outcome_auto_resolved", "M 795 330 C 825 330 825 71 855 71"),
        ("evaluator_loop", "outcome_unresolved_handoff_L2", "M 795 351 C 825 351 825 233 855 233"),
    ]

    # Draw edges first so nodes render on top
    for u, v, d in edges:
        is_active = (u, v) in active_edge_pairs or (u in visited_set and v == final_outcome_node)
        stroke = "#2563eb" if is_active else "#cbd5e1"
        stroke_w = "2.4" if is_active else "1.1"
        dash = "" if is_active else 'stroke-dasharray="3,3"'
        marker = 'url(#arr-active)' if is_active else 'url(#arr-inactive)'

        svg_parts.append(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{stroke_w}" {dash} marker-end="{marker}"/>')

    # Helper to draw a standard step node
    def draw_node(node_id: str, x: int, y: int, w: int, h: int, title: str, subtitle: str, node_type: str, is_decision: bool = False) -> None:
        visited = node_id in visited_set
        color_map = {
            "code": COLOR_CODE_API,
            "llm": COLOR_LLM_AGENT,
            "decision": COLOR_DECISION,
            "human": COLOR_HUMAN_LOOP,
            "blocked": COLOR_BLOCKED_FAILED,
        }
        accent = color_map.get(node_type, COLOR_CODE_API)

        if visited:
            bg_fill = "#ffffff"
            border_col = accent
            border_w = 2.2
            opacity = 1.0
            title_col = "#0f172a"
            sub_col = accent
            badge_bg = accent
            badge_fg = "#ffffff"
        else:
            bg_fill = "#f8fafc"
            border_col = "#cbd5e1"
            border_w = 1.0
            opacity = 0.40
            title_col = "#94a3b8"
            sub_col = "#cbd5e1"
            badge_bg = "#e2e8f0"
            badge_fg = "#94a3b8"

        dash_attr = "" if visited else 'stroke-dasharray="3,3"'

        # Decision diamond indicator or normal rounded rect
        svg_parts.append(f'<g opacity="{opacity}">')
        svg_parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{bg_fill}" stroke="{border_col}" stroke-width="{border_w}" {dash_attr}/>')

        if is_decision:
            # Small decision badge
            svg_parts.append(f'<polygon points="{x+8},{y+h//2} {x+14},{y+h//2-6} {x+20},{y+h//2} {x+14},{y+h//2+6}" fill="{accent if visited else "#cbd5e1"}"/>')
            text_x = x + 26
        else:
            text_x = x + 10

        svg_parts.append(f'<text x="{text_x}" y="{y+18}" fill="{title_col}" font-size="12" font-weight="700">{_esc(title)}</text>')
        svg_parts.append(f'<text x="{text_x}" y="{y+31}" fill="{sub_col}" font-size="9.5" font-weight="600">{_esc(subtitle)}</text>')

        # Type pill on right
        badge_text = "DECISION" if is_decision else node_type.upper()
        badge_w = 54 if is_decision else 42
        svg_parts.append(f'<rect x="{x+w-badge_w-6}" y="{y+10}" width="{badge_w}" height="16" rx="3" fill="{badge_bg}"/>')
        svg_parts.append(f'<text x="{x+w-badge_w//2-6}" y="{y+22}" fill="{badge_fg}" font-size="8.5" font-weight="700" text-anchor="middle">{badge_text}</text>')
        svg_parts.append('</g>')

    # 1. Stage 1 Nodes
    draw_node("receive_request", 40, 50, 190, 38, "Receive Request", "HTTP Ingestion", "code")
    draw_node("auth", 40, 106, 190, 38, "Auth Check", "Bearer token validation", "code")
    draw_node("rate_limit", 40, 162, 190, 38, "Rate Limiter", "10 req / 60s window", "code")
    draw_node("kill_switch", 40, 218, 190, 38, "Kill Switch", "Emergency human routing", "decision", is_decision=True)
    draw_node("ticket", 40, 274, 190, 38, "Ticket & Session", "Create or append ticket", "decision", is_decision=True)
    draw_node("agent_call", 40, 330, 190, 38, "Call Agent Service", "Timeout & 1 retry", "code")

    # 2. Stage 2 Nodes
    draw_node("input_guardrail", 300, 50, 190, 38, "Input Guardrail", "Injection / cred disclosure", "blocked" if "blocked_by_guardrail" in visited_set else "code")
    draw_node("keyword_scan", 300, 106, 190, 38, "Keyword Scan", "Regex bilingual scan", "code")
    draw_node("triage", 300, 162, 190, 38, "Triage Agent", "Category & severity rules", "llm")
    draw_node("missing_info_check", 300, 218, 190, 38, "Missing Info?", "Follow-up question gate", "decision", is_decision=True)
    draw_node("routing_rules", 300, 274, 190, 38, "Routing Rules", "Security keyword net", "decision", is_decision=True)
    draw_node("immediate_alert", 300, 330, 190, 38, "SOC / On-Call Alert", "Immediate notification", "human")

    # 3. Stage 3 Nodes
    draw_node("plan", 555, 50, 240, 38, "Planner Agent", "Allowlist tool plan", "llm")

    # Parallel Workers Group Box
    pw_opacity = 1.0 if workers_visited else 0.40
    pw_border = COLOR_CODE_API if workers_visited else "#cbd5e1"
    pw_border_w = 2.0 if workers_visited else 1.0
    pw_dash = "" if workers_visited else 'stroke-dasharray="3,3"'

    svg_parts.append(f'<g opacity="{pw_opacity}">')
    svg_parts.append(f'<rect x="555" y="102" width="240" height="135" rx="6" fill="#ffffff" stroke="{pw_border}" stroke-width="{pw_border_w}" {pw_dash}/>')
    svg_parts.append(f'<rect x="555" y="102" width="240" height="22" rx="6" fill="{"#eff6ff" if workers_visited else "#f1f5f9"}"/>')
    svg_parts.append(f'<text x="565" y="117" fill="{COLOR_CODE_API if workers_visited else "#94a3b8"}" font-size="10.5" font-weight="700">PARALLEL WORKERS (CONCURRENT)</text>')

    tool_y = 138
    for tool_id, tool_label in STANDARD_TOOLS:
        st_text, st_bg, st_fg = tool_status_map[tool_id]
        svg_parts.append(f'<text x="565" y="{tool_y}" fill="#334155" font-size="10" font-family="Consolas, monospace">{tool_label}</text>')
        svg_parts.append(f'<rect x="735" y="{tool_y-10}" width="52" height="14" rx="3" fill="{st_bg}"/>')
        svg_parts.append(f'<text x="761" y="{tool_y}" fill="{st_fg}" font-size="8.5" font-weight="700" text-anchor="middle">{st_text}</text>')
        tool_y += 20
    svg_parts.append('</g>')

    # Aggregate Evidence Node
    draw_node("aggregate_evidence", 555, 248, 240, 36, "Aggregate Evidence", "Critical tools sufficiency", "decision", is_decision=True)

    # Evaluator Loop Group Box
    el_opacity = 1.0 if eval_visited else 0.40
    el_border = COLOR_LLM_AGENT if eval_visited else "#cbd5e1"
    el_border_w = 2.0 if eval_visited else 1.0
    el_dash = "" if eval_visited else 'stroke-dasharray="3,3"'

    svg_parts.append(f'<g opacity="{el_opacity}">')
    svg_parts.append(f'<rect x="555" y="296" width="240" height="110" rx="6" fill="#ffffff" stroke="{el_border}" stroke-width="{el_border_w}" {el_dash}/>')
    svg_parts.append(f'<rect x="555" y="296" width="240" height="22" rx="6" fill="{"#faf5ff" if eval_visited else "#f1f5f9"}"/>')
    svg_parts.append(f'<text x="565" y="311" fill="{COLOR_LLM_AGENT if eval_visited else "#94a3b8"}" font-size="10.5" font-weight="700">EVALUATOR-OPTIMIZER LOOP (MAX 3)</text>')

    att_y = 333
    for att_idx in range(1, 4):
        att_st_text, att_st_bg, att_st_fg = attempts_status[att_idx - 1]
        svg_parts.append(f'<text x="565" y="{att_y}" fill="#334155" font-size="10" font-weight="600">Attempt {att_idx} (Draft & Verdict)</text>')
        svg_parts.append(f'<rect x="725" y="{att_y-10}" width="62" height="14" rx="3" fill="{att_st_bg}"/>')
        svg_parts.append(f'<text x="756" y="{att_y}" fill="{att_st_fg}" font-size="8" font-weight="700" text-anchor="middle">{att_st_text}</text>')
        att_y += 24
    svg_parts.append('</g>')

    # 4. Stage 4: Six Outcome Boxes
    outcome_defs = [
        ("outcome_auto_resolved", 855, 50, "Auto-Resolved", "Resolved by agent proposal", COLOR_SUCCESS),
        ("outcome_needs_more_info", 855, 104, "Needs More Info", "Awaiting user clarification", COLOR_DECISION),
        ("outcome_escalated_to_human", 855, 158, "Escalated to Human", "SOC / On-Call review queue", COLOR_HUMAN_LOOP),
        ("outcome_unresolved_handoff_L2", 855, 212, "Unresolved L2 Handoff", "Assigned L2 with findings", COLOR_HUMAN_LOOP),
        ("outcome_blocked_by_guardrail", 855, 266, "Blocked by Guardrail", "Refusal template emitted", COLOR_BLOCKED_FAILED),
        ("outcome_system_error", 855, 320, "System Error (WF-ERR)", "Manual triage required", COLOR_BLOCKED_FAILED),
    ]

    for node_id, ox, oy, otitle, odesc, ocol in outcome_defs:
        is_winner = node_id == final_outcome_node
        is_visited = node_id in visited_set

        if is_winner:
            obg = "#ffffff"
            oborder = ocol
            oborder_w = 3.5
            o_opacity = 1.0
            filter_attr = 'filter="url(#glow-outcome)"'
            win_badge = f'<rect x="{ox+100}" y="{oy+10}" width="82" height="15" rx="3" fill="{ocol}"/><text x="{ox+141}" y="{oy+21}" fill="#ffffff" font-size="8" font-weight="700" text-anchor="middle">&#9733; OUTCOME</text>'
            otitle_col = ocol
        elif is_visited:
            obg = "#ffffff"
            oborder = ocol
            oborder_w = 2.0
            o_opacity = 0.95
            filter_attr = ""
            win_badge = ""
            otitle_col = "#0f172a"
        else:
            obg = "#f8fafc"
            oborder = "#cbd5e1"
            oborder_w = 1.0
            o_opacity = 0.35
            filter_attr = ""
            win_badge = ""
            otitle_col = "#94a3b8"

        dash_attr = "" if (is_winner or is_visited) else 'stroke-dasharray="3,3"'

        svg_parts.append(f'<g opacity="{o_opacity}">')
        svg_parts.append(f'<rect x="{ox}" y="{oy}" width="190" height="42" rx="6" fill="{obg}" stroke="{oborder}" stroke-width="{oborder_w}" {dash_attr} {filter_attr}/>')
        svg_parts.append(f'<text x="{ox+10}" y="{oy+18}" fill="{otitle_col}" font-size="11.5" font-weight="700">{_esc(otitle)}</text>')
        svg_parts.append(f'<text x="{ox+10}" y="{oy+32}" fill="{"#64748b" if (is_winner or is_visited) else "#cbd5e1"}" font-size="9">{_esc(odesc)}</text>')
        svg_parts.append(win_badge)
        svg_parts.append('</g>')

    # Legend across the bottom
    svg_parts.append('<g transform="translate(40, 470)">')
    legend_items = [
        ("Code / API", COLOR_CODE_API),
        ("LLM Agent", COLOR_LLM_AGENT),
        ("Decision", COLOR_DECISION),
        ("Success", COLOR_SUCCESS),
        ("Human Review", COLOR_HUMAN_LOOP),
        ("Blocked / Error", COLOR_BLOCKED_FAILED),
    ]
    lx = 0
    for ltitle, lcol in legend_items:
        svg_parts.append(f'<rect x="{lx}" y="0" width="12" height="12" rx="3" fill="{lcol}"/>')
        svg_parts.append(f'<text x="{lx+18}" y="10" fill="#475569" font-size="10" font-weight="600">{ltitle}</text>')
        lx += 120

    svg_parts.append(f'<rect x="{lx+20}" y="5" width="24" height="2" fill="#2563eb"/>')
    svg_parts.append(f'<text x="{lx+50}" y="10" fill="#475569" font-size="10" font-weight="600">Active Path</text>')
    svg_parts.append(f'<rect x="{lx+130}" y="5" width="24" height="2" fill="#cbd5e1" stroke-dasharray="3,3"/>')
    svg_parts.append(f'<text x="{lx+160}" y="10" fill="#94a3b8" font-size="10" font-weight="600">Skipped Path</text>')
    svg_parts.append('</g>')

    svg_parts.append('</svg>')
    svg_parts.append('</div>')

    return '\n'.join(svg_parts)
