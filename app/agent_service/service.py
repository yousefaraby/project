"""Agent Service: process_incident full pipeline."""
from __future__ import annotations

import time
from typing import Any

from app.agent_service.guardrail import check_input
from app.agent_service.keyword_scan import scan_keywords
from app.agent_service.orchestrator import (
    IncidentOrchestrator,
    aggregate_evidence,
    filter_plan_tools,
)
from app.agent_service.routing import alert_channel, decide_route
from app.agents.base import (
    Evaluator as EvaluatorProtocol,
    Planner,
    Trace,
    TriageAgent,
    Troubleshooter,
)
from app.agents.mock import (
    Evaluator,
    MockPlanner,
    MockTriageAgent,
    MockTroubleshooter,
    follow_up_question,
)
from app.services import fixtures
from app.services.itsm import TicketStatus, itsm
from app.services.messaging import (
    ReplyContext,
    notify,
    reply_idempotency_key,
    send_reply,
)

from app.controls import controls

# Swap points: replace with real implementations later.
triage_agent: TriageAgent = MockTriageAgent()
planner: Planner = MockPlanner()
orchestrator: IncidentOrchestrator = IncidentOrchestrator(per_tool_timeout_s=2.0)
troubleshooter: Troubleshooter = MockTroubleshooter()
evaluator: EvaluatorProtocol = Evaluator()


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


def _result(outcome: str, trace: Trace, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "incident_id": "",
        "category": "",
        "severity": "",
        "security_flag": False,
        "outcome": outcome,
        "reply_text": "",
        "reply_sent": False,
        "requires_human": False,
        "triage": {},
        "kw_flag": False,
        "keyword_hits": [],
        "injection_detected": False,
        "escalation_reasons": [],
        "plan": {},
        "findings": {},
        "tool_results": [],
        "tool_errors": [],
        "eval_attempts": 0,
        "eval_verdicts": [],
        "draft": "",
        "notes": "",
        "immediate_alert": None,
    }
    base.update(kw)
    triage = base.get("triage", {})
    if triage:
        if not base.get("category"):
            base["category"] = triage.get("category", "")
        if not base.get("severity"):
            base["severity"] = triage.get("severity", "")
        if not base.get("security_flag"):
            base["security_flag"] = triage.get("security_flag", False)
    base["trace"] = trace.to_list()
    return base


async def process_incident(incident: dict[str, Any], session_ctx: dict[str, Any]) -> dict[str, Any]:
    trace = Trace()
    message: str = incident.get("message", "")
    user_id: str = incident.get("user_id", "")
    incident_id: str = incident.get("incident_id", "")
    prior = incident.get("prior_findings") or {}

    # Fault injection check (none / timeout / exception / invalid response)
    fault = getattr(controls, "agent_service_fault", "none")
    if fault == "timeout":
        raise asyncio.TimeoutError("Agent Service fault injection: simulated timeout")
    elif fault == "invalid response" or fault == "invalid":
        return {"outcome": "illegal_outcome_for_testing", "bad_response": True}
    elif fault == "exception" or (controls.agent_fault and fault == "none"):
        raise RuntimeError("Agent Service fault injection: simulated failure")

    # Ensure ticket exists in ITSM if an incident_id is provided
    if incident_id:
        try:
            itsm.get_ticket(incident_id)
        except KeyError:
            try:
                itsm.create_ticket(user_id, summary=message[:80], description=message, ticket_id=incident_id)
            except Exception:
                pass

    # 0. input guardrail ----------------------------------------------------------------
    t0 = time.perf_counter()
    g = check_input(message)
    if g.blocked:
        trace.add("input_guardrail", "blocked", message[:60], f"blocked: {g.category} ({g.matched[0][:40]})",
                  branch="block", duration_ms=_ms(t0))
        return _result(
            "blocked_by_guardrail", trace,
            incident_id=incident_id,
            injection_detected=g.injection,
            escalation_reasons=[f"guardrail:{g.category}"],
            notes=f"Guardrail category={g.category}",
        )
    trace.add("input_guardrail", "code", message[:60], "pass", branch="pass", duration_ms=_ms(t0))

    # 0b. security keyword scan -----------------------------------------------------------
    t0 = time.perf_counter()
    hits = scan_keywords(message)
    kw_flag = bool(hits)
    trace.add("keyword_scan", "code", message[:60], f"hits={hits}" if hits else "no hits",
              branch="kw_flag" if kw_flag else "clean", duration_ms=_ms(t0))

    # 1. triage ---------------------------------------------------------------------------
    t0 = time.perf_counter()
    user = fixtures.get_user(user_id) or {}
    triage_text = message
    if incident.get("is_follow_up") and prior.get("pending_question") and prior.get("original_message"):
        # Answer to our own follow-up question: triage the original message + the answer.
        triage_text = f"{prior['original_message']} {message}"
    triage = await triage_agent.triage(triage_text, {"user_id": user_id, "laptop_id": user.get("laptop_id")})
    trace.add("triage", "llm", triage_text[:60],
              f"{triage['category']}/{triage['severity']} security_flag={triage['security_flag']} "
              f"missing={triage['missing_info']}", duration_ms=_ms(t0))

    # Routing reasons are computed now so a security signal is never parked behind a question.
    reasons = decide_route(triage, kw_flag)

    # 1b. missing info? -------------------------------------------------------------------
    if triage["missing_info"] and not reasons:
        question = follow_up_question(triage["missing_info"])
        trace.add("missing_info_check", "decision", str(triage["missing_info"]), "ask user", branch="needs_more_info")
        return _result(
            "needs_more_info", trace,
            incident_id=incident_id,
            reply_text=question,
            triage=triage,
            kw_flag=kw_flag,
            keyword_hits=hits,
            findings={"triage": triage, "original_message": triage_text, "pending_question": question},
        )
    trace.add("missing_info_check", "decision", str(triage["missing_info"]),
              "continue" if not triage["missing_info"] else "continue (security routing overrides question)",
              branch="continue")

    # 2. routing rules --------------------------------------------------------------------
    t0 = time.perf_counter()
    requires_human = bool(reasons)
    trace.add("routing_rules", "decision", f"{triage['category']}/{triage['severity']} kw_flag={kw_flag}",
              f"reasons={reasons}" if reasons else "no escalation reasons",
              branch="requires_human" if requires_human else "agent_continues", duration_ms=_ms(t0))

    alert = None
    if requires_human:
        t0 = time.perf_counter()
        channel = alert_channel(reasons)
        alert = notify(channel, incident_id,
                       f"Immediate escalation ({', '.join(reasons)}): {triage['summary']}",
                       severity=triage["severity"] if triage["severity"] in ("high", "critical") else "high")
        trace.add("immediate_alert", "human", f"reasons={reasons}", f"{channel} alerted at {alert['ts']}",
                  branch=channel, duration_ms=_ms(t0))

    # 3. plan -----------------------------------------------------------------------------
    t0 = time.perf_counter()
    context = {
        "user_id": user_id,
        "laptop_id": user.get("laptop_id"),
        "message": message,
        "incident_id": incident_id,
        "is_follow_up": incident.get("is_follow_up", False),
    }
    raw_plan = await planner.plan(triage, context)
    plan = filter_plan_tools(raw_plan)
    trace.add(
        "plan", "llm", f"category={triage['category']}",
        f"workers={plan.get('workers')} tools={plan.get('tools')}",
        branch="plan", duration_ms=_ms(t0),
    )

    # 4. orchestrate workers concurrently -------------------------------------------------
    t0 = time.perf_counter()
    worker_results = await orchestrator.run(plan, context)
    for wr in worker_results:
        trace.add(
            f"worker_{wr['worker']}", "code", wr["worker"],
            f"status={wr['status']} findings={len(wr.get('findings', []))}",
            branch=wr["status"], duration_ms=wr.get("latency", 0.0),
        )

    # 4b. aggregate evidence --------------------------------------------------------------
    t0 = time.perf_counter()
    findings, tool_results, tool_errors, enough_evidence = aggregate_evidence(triage["category"], worker_results)
    trace.add(
        "aggregate_evidence", "decision",
        f"results={len(tool_results)} errors={len(tool_errors)}",
        f"enough_evidence={enough_evidence}",
        branch="enough" if enough_evidence else "not_enough",
        duration_ms=_ms(t0),
    )

    # Check whether critical tools for the category succeeded
    if not enough_evidence:
        trace.add("evidence_check", "decision", f"enough={enough_evidence}", "critical tools failed", branch="not_enough")
        if requires_human:
            # HARD RULE: requires_human forces escalated_to_human
            trace.add("hard_rule_override", "decision", "requires_human=True overrides insufficient evidence", "escalated_to_human", branch="escalated_to_human")
            return _result(
                "escalated_to_human", trace,
                incident_id=incident_id,
                requires_human=True,
                triage=triage,
                kw_flag=kw_flag,
                keyword_hits=hits,
                escalation_reasons=reasons + ["insufficient_evidence: critical tools failed"],
                immediate_alert=alert,
                plan=plan,
                findings={"triage": triage, **findings},
                tool_results=tool_results,
                tool_errors=tool_errors,
                draft="Diagnostics incomplete: critical tools failed.",
                notes=f"Critical diagnostic tools failed for {triage['category']}. Escalated to human.",
            )
        else:
            return _result(
                "unresolved_handoff_L2", trace,
                incident_id=incident_id,
                requires_human=True,
                triage=triage,
                kw_flag=kw_flag,
                keyword_hits=hits,
                escalation_reasons=reasons + ["insufficient_evidence: critical tools failed"],
                plan=plan,
                findings={"triage": triage, **findings},
                tool_results=tool_results,
                tool_errors=tool_errors,
                notes=f"Critical diagnostic tools failed for {triage['category']}. Handoff to L2 with partial findings.",
                eta="2 business hours",
            )

    # 5. Evaluator-optimizer loop (MAX 3 attempts) ----------------------------------------
    eval_attempts = 0
    eval_verdicts: list[dict[str, Any]] = []
    approved = False
    proposal: dict[str, Any] = {}
    critique: str | None = None

    for attempt in range(1, 4):
        eval_attempts = attempt
        t0 = time.perf_counter()
        proposal = await troubleshooter.propose(findings, critique, context)
        trace.add(
            f"troubleshooter_attempt_{attempt}", "llm",
            critique or "initial_attempt",
            f"draft: {proposal.get('text', '')[:60]} ({len(proposal.get('claims', []))} claims)",
            branch=f"attempt_{attempt}", duration_ms=_ms(t0),
        )

        t0 = time.perf_counter()
        verdict = await evaluator.evaluate(proposal, {**findings, "tool_errors": tool_errors})
        eval_verdicts.append({"attempt": attempt, **verdict})
        trace.add(
            f"evaluator_verdict_{attempt}", "decision",
            proposal.get("text", "")[:60],
            f"approved={verdict['approved']} issues={len(verdict['issues'])}",
            branch="approved" if verdict["approved"] else "rejected",
            duration_ms=_ms(t0),
        )

        if verdict["approved"]:
            approved = True
            break
        critique = verdict.get("critique")

    draft_text = proposal.get("text", "")

    # Loop exhausted after 3 rejections
    if not approved:
        trace.add("evaluator_loop", "decision", "3 attempts exhausted", "loop_exhausted", branch="exhausted")
        if requires_human:
            # HARD RULE: requires_human forces escalated_to_human
            trace.add("hard_rule_override", "decision", "requires_human=True overrides loop exhaustion", "escalated_to_human", branch="escalated_to_human")
            outcome = "escalated_to_human"
        else:
            outcome = "unresolved_handoff_L2"

        return _result(
            outcome, trace,
            incident_id=incident_id,
            requires_human=True,
            triage=triage,
            kw_flag=kw_flag,
            keyword_hits=hits,
            escalation_reasons=reasons + (["evaluator_rejections_exhausted"] if not requires_human else []),
            immediate_alert=alert,
            plan=plan,
            findings={"triage": triage, **findings},
            tool_results=tool_results,
            tool_errors=tool_errors,
            eval_attempts=eval_attempts,
            eval_verdicts=eval_verdicts,
            draft=draft_text,
            notes=f"Evaluator rejected 3 drafts: {critique}",
            eta="4 business hours" if outcome == "unresolved_handoff_L2" else None,
        )

    # 6. Evaluator approved -> evaluate HARD RULE requires_human -------------------------
    trace.add("evaluator_loop", "decision", f"approved on attempt {eval_attempts}", "approved", branch="approved")

    if requires_human:
        # HARD RULE: requires_human forces escalated_to_human even when evaluator approved.
        # Draft goes only into internal note; send_reply is NEVER called.
        outcome = "escalated_to_human"
        trace.add("hard_rule_override", "decision", "requires_human=True overrides approval", "escalated_to_human", branch="escalated_to_human")
        if incident_id:
            try:
                itsm.add_internal_note(incident_id, f"[HUMAN REVIEW QUEUE]\nApproved draft for specialist review:\n{draft_text}")
            except Exception:
                pass

        return _result(
            outcome="escalated_to_human",
            trace=trace,
            incident_id=incident_id,
            reply_text="",
            reply_sent=False,
            requires_human=True,
            triage=triage,
            kw_flag=kw_flag,
            keyword_hits=hits,
            escalation_reasons=reasons,
            immediate_alert=alert,
            plan=plan,
            findings={"triage": triage, **findings},
            tool_results=tool_results,
            tool_errors=tool_errors,
            eval_attempts=eval_attempts,
            eval_verdicts=eval_verdicts,
            draft=draft_text,
            notes="Draft approved by evaluator, but escalated due to requires_human=True hard rule.",
        )

    # Check if an actionable resolution was found
    has_actionable_resolution = any(
        ("KB match" in c.get("claim", "") or "applies" in c.get("claim", "") or "outdated" in c.get("claim", "") or "locked" in c.get("claim", ""))
        and not ("no automated resolution" in c.get("claim", "").lower() or "no solution" in c.get("claim", "").lower())
        for c in proposal.get("claims", [])
    ) and not (tool_errors and not any("KB match" in c.get("claim", "") or "applies" in c.get("claim", "") for c in proposal.get("claims", [])))

    if not has_actionable_resolution:
        trace.add("resolution_check", "decision", "no actionable resolution", "unresolved_handoff_L2", branch="unresolved_handoff_L2")
        return _result(
            outcome="unresolved_handoff_L2",
            trace=trace,
            incident_id=incident_id,
            requires_human=True,
            triage=triage,
            kw_flag=kw_flag,
            keyword_hits=hits,
            escalation_reasons=reasons + ["no_actionable_kb_resolution"],
            plan=plan,
            findings={"triage": triage, **findings},
            tool_results=tool_results,
            tool_errors=tool_errors,
            eval_attempts=eval_attempts,
            eval_verdicts=eval_verdicts,
            draft=draft_text,
            notes="No automated resolution steps found in KB. Handoff to Level 2.",
            eta="4 business hours",
        )

    # Action tools path (requires_human is False)
    t0 = time.perf_counter()
    reply_sent = False
    try:
        if incident_id:
            itsm.update_ticket(incident_id, status=TicketStatus.PENDING_USER_CONFIRMATION)
            itsm.add_internal_note(incident_id, f"Auto-resolution draft applied:\n{draft_text}")

        key = reply_idempotency_key(incident.get("idempotency_key", f"{incident_id}:msg1"))
        reply_rec = send_reply(
            ReplyContext(incident_id, user_id, requires_human=False),
            incident_id, user_id, draft_text,
            idempotency_key=key,
        )
        reply_sent = not reply_rec.get("duplicate", False)
        outcome = "auto_resolved"
        trace.add("action_tools", "code", "update_ticket + send_reply", "auto_resolved", branch="auto_resolved", duration_ms=_ms(t0))
    except Exception as e:
        outcome = "action_failed"
        reply_sent = False
        if incident_id:
            try:
                itsm.set_needs_manual(incident_id, True)
                itsm.tag_ticket(incident_id, "NEEDS-MANUAL")
                itsm.add_internal_note(incident_id, f"Action execution failed: {e}\nDraft reply not sent:\n{draft_text}")
                notify("IT-ops", incident_id, f"Action tool failed: {e}", severity="high")
            except Exception:
                pass
        trace.add("action_tools", "code", f"action failed: {e}", "action_failed", branch="action_failed", duration_ms=_ms(t0))

    return _result(
        outcome=outcome,
        trace=trace,
        incident_id=incident_id,
        reply_text=draft_text if outcome == "auto_resolved" else "",
        reply_sent=reply_sent,
        requires_human=False,
        triage=triage,
        kw_flag=kw_flag,
        keyword_hits=hits,
        escalation_reasons=reasons,
        plan=plan,
        findings={"triage": triage, **findings},
        tool_results=tool_results,
        tool_errors=tool_errors,
        eval_attempts=eval_attempts,
        eval_verdicts=eval_verdicts,
        draft=draft_text,
        notes="Resolution proposed and action tools executed." if outcome == "auto_resolved" else "Action tool failed.",
    )
