"""Backend workflow: auth -> rate limit -> kill switch -> session -> ticket -> agent -> outcome -> audit."""
from __future__ import annotations

import logging
import time
from typing import Any

from app.agent_service.service import process_incident
from app.agents.base import Trace
from app.backend.agent_client import AgentCallFailed, AgentClient
from app.backend.auth import RateLimiter, verify_bearer
from app.backend.schemas import SYSTEM_ERROR, AgentResult
from app.controls import controls
from app.services.audit import AuditRecord, redact, write_audit
from app.services.data import register_reset
from app.services.itsm import Ticket, TicketStatus, itsm
from app.services.messaging import (
    ReplyContext, notify, reply_idempotency_key, send_reply, send_template,
)
from app.services.session import Session, sessions

log = logging.getLogger("ir.backend")

AGENT_TIMEOUT_S = 15.0
DEFAULT_L2_ETA = "4 business hours"
KILL_SWITCH_MESSAGE = ("The automated assistant is temporarily unavailable. "
                       "Your request has been routed to the human service desk.")
NEEDS_MANUAL = "NEEDS-MANUAL"

rate_limiter = RateLimiter(limit=10, window_s=60.0)
agent_client = AgentClient(process_incident, timeout_s=AGENT_TIMEOUT_S, max_retries=1)
review_queue: list[dict[str, Any]] = []  # human review queue for escalations


def _reset_backend() -> None:
    rate_limiter.reset()
    agent_client.clear_cache()
    agent_client.fn = process_incident
    agent_client.timeout_s = AGENT_TIMEOUT_S
    review_queue.clear()


register_reset(_reset_backend)


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


def _response(status: int, trace: Trace, t_start: float, **kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"status": status, "outcome": None, "ticket_id": None, "reply": None,
                           "requires_human": None, "error": None}
    out.update(kw)
    out["duration_ms"] = _ms(t_start)
    out["trace"] = trace.to_list()
    return out


# --------------------------------------------------------------------------- entrypoint

async def handle_request(user_id: str, message: str, session_id: str,
                         authorization: str | None = None) -> dict[str, Any]:
    t_start = time.perf_counter()
    trace = Trace()
    session_id = session_id or user_id
    trace.add("receive_request", "code", f"user={user_id} session={session_id}", f"{len(message)} chars")

    # 1. auth + rate limit
    t0 = time.perf_counter()
    if not verify_bearer(authorization, user_id):
        log.warning("auth failed for user=%s", user_id)
        trace.add("auth", "blocked", f"user={user_id}", "401 unauthorized", branch="reject", duration_ms=_ms(t0))
        return _response(401, trace, t_start, error="unauthorized")
    trace.add("auth", "code", f"user={user_id}", "ok", duration_ms=_ms(t0))

    t0 = time.perf_counter()
    if not rate_limiter.allow(user_id):
        log.warning("rate limit exceeded for user=%s", user_id)
        trace.add("rate_limit", "blocked", f"user={user_id}", "429 too many requests", branch="reject",
                  duration_ms=_ms(t0))
        return _response(429, trace, t_start, error="rate_limited")
    trace.add("rate_limit", "code", f"user={user_id}", "ok", duration_ms=_ms(t0))

    # 2. kill switch
    if controls.kill_switch:
        log.info("kill switch ON: routing user=%s to human desk", user_id)
        trace.add("kill_switch", "decision", "ON", "routed to human service desk", branch="human_desk")
        return _response(200, trace, t_start, routed_to="human_service_desk", reply=KILL_SWITCH_MESSAGE)
    trace.add("kill_switch", "decision", "OFF", "continue", branch="agent")

    # session ownership
    existing = sessions.peek(session_id)
    if existing and existing.user_id != user_id:
        log.warning("session %s does not belong to user=%s", session_id, user_id)
        trace.add("load_session", "blocked", session_id, "403 session belongs to another user", branch="reject")
        return _response(403, trace, t_start, error="forbidden")

    state: dict[str, Any] = {"ticket_id": None, "idem": None}
    try:
        return await _run(state, user_id, message, session_id, trace, t_start)
    except Exception as e:  # noqa: BLE001 - any failure goes to WF-ERR
        log.exception("unexpected failure in pipeline")
        return _wf_err(state, user_id, message, session_id, trace, t_start,
                       f"pipeline exception: {type(e).__name__}: {e}")


async def _run(state: dict[str, Any], user_id: str, message: str, session_id: str,
               trace: Trace, t_start: float) -> dict[str, Any]:
    # 3. load session
    t0 = time.perf_counter()
    session = sessions.get(session_id, user_id=user_id)
    trace.add("load_session", "code", session_id,
              f"open_incident={session.open_incident_id} history={len(session.history)}", duration_ms=_ms(t0))

    # 4. open incident? append : create
    t0 = time.perf_counter()
    safe_msg = redact(message)
    ticket: Ticket | None = None
    if session.open_incident_id:
        try:
            ticket = itsm.get_ticket(session.open_incident_id)
        except KeyError:
            ticket = None
    if ticket is not None:
        itsm.append_to_ticket(ticket.ticket_id, safe_msg, author="user")
        prior_findings = dict(session.last_findings)
        branch = "append"
    else:
        ticket = itsm.create_ticket(user_id, summary=safe_msg[:80], description=safe_msg)
        prior_findings = {}
        branch = "create"
    state["ticket_id"] = ticket.ticket_id
    message_number = 1 + sum(1 for c in ticket.comments if c["author"] == "user")
    idem = f"{ticket.ticket_id}:msg{message_number}"
    state["idem"] = idem
    trace.add("ticket", "decision", f"open_incident={session.open_incident_id}",
              f"{branch} {ticket.ticket_id} (msg #{message_number})", branch=branch, duration_ms=_ms(t0))

    # 5-6. call agent (timeout, 1 retry, idempotency) + validate
    incident = {
        "incident_id": ticket.ticket_id,
        "user_id": user_id,
        "message": safe_msg,
        "message_number": message_number,
        "idempotency_key": idem,
        "is_follow_up": branch == "append",
        "prior_findings": prior_findings,
    }
    session_ctx = session.model_dump()
    try:
        result = await agent_client.call(incident, session_ctx, trace)
    except AgentCallFailed as e:
        return _wf_err(state, user_id, message, session_id, trace, t_start, f"agent call failed: {e}")
    trace.extend(result.trace)

    # 7. switch on outcome
    reply_text, backend_sent = _apply_outcome(result, ticket.ticket_id, user_id, idem, trace)
    reply_sent = result.reply_sent or backend_sent

    # 8. audit + session memory
    t0 = time.perf_counter()
    write_audit(AuditRecord(
        incident_id=ticket.ticket_id, user_id=user_id, redacted_message=safe_msg,
        triage=result.triage, kw_flag=result.kw_flag, escalation_reasons=result.escalation_reasons,
        plan=result.plan, tool_results=result.tool_results, tool_errors=result.tool_errors,
        eval_attempts=result.eval_attempts, eval_verdicts=result.eval_verdicts,
        outcome=result.outcome, reply_sent=reply_sent, duration_ms=_ms(t_start),
    ))
    trace.add("write_audit", "code", ticket.ticket_id, f"outcome={result.outcome}", duration_ms=_ms(t0))

    t0 = time.perf_counter()
    _update_session(session, safe_msg, reply_text, result,
                    keep_open=result.outcome != "blocked_by_guardrail", ticket_id=ticket.ticket_id)
    trace.add("update_session", "code", session_id,
              f"open_incident={sessions.get(session_id).open_incident_id}", duration_ms=_ms(t0))

    return _response(200, trace, t_start, outcome=result.outcome, ticket_id=ticket.ticket_id,
                     reply=reply_text, requires_human=result.requires_human)


# --------------------------------------------------------------------------- outcome switch

def _apply_outcome(r: AgentResult, ticket_id: str, user_id: str, idem: str,
                   trace: Trace) -> tuple[str | None, bool]:
    """Executes backend actions for the outcome. Returns (text shown to user, backend_sent_reply)."""
    t0 = time.perf_counter()
    key = reply_idempotency_key(idem)
    reply: str | None = None
    sent = False

    if r.outcome == "auto_resolved":
        if r.reply_sent:
            reply = r.reply_text
        else:
            rec = send_reply(ReplyContext(ticket_id, user_id, r.requires_human), ticket_id, user_id,
                             r.reply_text, idempotency_key=key)
            reply, sent = r.reply_text, not rec.get("duplicate", False)
        itsm.update_ticket(ticket_id, status=TicketStatus.PENDING_USER_CONFIRMATION)
        step_type, out = "code", "reply sent; ticket Pending user confirmation"

    elif r.outcome == "needs_more_info":
        rec = send_reply(ReplyContext(ticket_id, user_id, r.requires_human), ticket_id, user_id,
                         r.reply_text, idempotency_key=key)
        reply, sent = r.reply_text, not rec.get("duplicate", False)
        itsm.update_ticket(ticket_id, status=TicketStatus.WAITING_FOR_USER)
        step_type, out = "code", "follow-up question sent; ticket Waiting for user"

    elif r.outcome == "escalated_to_human":
        security = bool(r.kw_flag or r.injection_detected or str(r.triage.get("category", "")).lower() == "security")
        channel = "SOC" if security else "on-call"
        notify(channel, ticket_id, f"Escalation: {', '.join(r.escalation_reasons) or 'agent escalated'}",
               severity=str(r.triage.get("severity", "high")))
        rec = send_template("holding", ticket_id, user_id, idempotency_key=key)  # reply_text ignored
        reply, sent = rec["text"], not rec.get("duplicate", False)
        itsm.update_ticket(ticket_id, status=TicketStatus.OPEN)
        itsm.tag_ticket(ticket_id, "human-review")
        itsm.add_internal_note(ticket_id, _review_note(r))
        review_queue.append({"ticket_id": ticket_id, "user_id": user_id, "draft": r.draft,
                             "evidence": r.findings, "escalation_reasons": r.escalation_reasons,
                             "triage": r.triage})
        step_type, out = "human", f"notified {channel}; holding template sent; queued for human review"

    elif r.outcome == "unresolved_handoff_L2":
        eta = r.eta or DEFAULT_L2_ETA
        itsm.assign_ticket(ticket_id, "L2")
        itsm.update_ticket(ticket_id, status=TicketStatus.ASSIGNED_L2)
        itsm.add_internal_note(ticket_id, _handoff_note(r))
        rec = send_template("l2_handoff", ticket_id, user_id, idempotency_key=key, eta=eta)
        reply, sent = rec["text"], not rec.get("duplicate", False)
        step_type, out = "human", f"assigned L2; user told ETA {eta}"

    elif r.outcome == "blocked_by_guardrail":
        log.warning("guardrail blocked request on %s (injection=%s)", ticket_id, r.injection_detected)
        rec = send_template("guardrail_refusal", ticket_id, user_id, idempotency_key=key)
        reply, sent = rec["text"], not rec.get("duplicate", False)
        itsm.set_flagged(ticket_id, True)
        itsm.tag_ticket(ticket_id, "guardrail-blocked")
        itsm.add_internal_note(ticket_id, f"Guardrail block. injection_detected={r.injection_detected}. "
                                          f"reasons={r.escalation_reasons}")
        if r.injection_detected:
            notify("Security", ticket_id, "Prompt-injection attempt blocked by guardrail", severity="high")
        step_type, out = "blocked", "refusal template sent; ticket flagged" + (
            "; Security alerted" if r.injection_detected else "")

    elif r.outcome == "action_failed":
        itsm.set_needs_manual(ticket_id, True)
        itsm.tag_ticket(ticket_id, NEEDS_MANUAL)
        notify("IT-ops", ticket_id, "Agent action failed; manual handling required", severity="high")
        itsm.add_internal_note(ticket_id, f"Action failed. Draft reply (not sent):\n{r.draft or r.reply_text}")
        step_type, out = "human", "tagged NEEDS-MANUAL; IT ops alerted; draft saved as internal note"

    else:  # unreachable: validated upstream
        raise ValueError(f"unknown outcome {r.outcome}")

    trace.add("outcome_switch", "decision", f"outcome={r.outcome}", out, branch=r.outcome)
    trace.add(f"outcome_{r.outcome}", step_type, ticket_id, out, duration_ms=_ms(t0))
    return reply, sent


def _review_note(r: AgentResult) -> str:
    return ("[HUMAN REVIEW QUEUE]\n"
            f"Escalation reasons: {r.escalation_reasons}\n"
            f"Triage: {r.triage}\n"
            f"Evidence: {r.findings}\n"
            f"Draft reply (NOT sent to user): {r.draft or r.reply_text}")


def _handoff_note(r: AgentResult) -> str:
    return ("[L2 HANDOFF]\n"
            f"Triage: {r.triage}\n"
            f"Findings: {r.findings}\n"
            f"Tool errors: {r.tool_errors}\n"
            f"Notes: {r.notes or '-'}")


def _update_session(session: Session, user_msg: str, reply: str | None, r: AgentResult,
                    keep_open: bool, ticket_id: str) -> None:
    session.history.append({"role": "user", "text": user_msg, "incident_id": ticket_id})
    if reply:
        session.history.append({"role": "assistant", "text": reply, "incident_id": ticket_id})
    session.open_incident_id = ticket_id if keep_open else None
    if r.findings:
        session.last_findings = {**session.last_findings, **r.findings}
    session.last_outcome = r.outcome
    sessions.save(session)


# --------------------------------------------------------------------------- WF-ERR

def _wf_err(state: dict[str, Any], user_id: str, message: str, session_id: str,
            trace: Trace, t_start: float, reason: str) -> dict[str, Any]:
    """Every sub-step is isolated so a failure here never masks the original error."""
    t0 = time.perf_counter()
    log.error("WF-ERR user=%s ticket=%s: %s", user_id, state.get("ticket_id"), reason)
    safe_msg = redact(message)
    ticket_id = state.get("ticket_id")
    done: list[str] = []

    if not ticket_id:
        try:
            ticket_id = itsm.create_ticket(user_id, summary=safe_msg[:80], description=safe_msg).ticket_id
            done.append("ticket created")
        except Exception:  # noqa: BLE001
            log.exception("WF-ERR: could not create ticket")
    if ticket_id:
        try:
            itsm.set_needs_manual(ticket_id, True)
            itsm.tag_ticket(ticket_id, NEEDS_MANUAL)
            itsm.add_internal_note(ticket_id, f"WF-ERR: {reason}")
            done.append("tagged NEEDS-MANUAL")
        except Exception:  # noqa: BLE001
            log.exception("WF-ERR: could not tag ticket")
    try:
        notify("IT-ops", ticket_id or "n/a", f"WF-ERR: {reason}", severity="high")
        done.append("IT ops alerted")
    except Exception:  # noqa: BLE001
        log.exception("WF-ERR: could not alert IT ops")
    reply = None
    try:
        key = f"{state.get('idem') or ticket_id}:wferr"
        rec = send_template("human_follow_up", ticket_id or "n/a", user_id, idempotency_key=key)
        reply = rec["text"]
        done.append("user informed")
    except Exception:  # noqa: BLE001
        log.exception("WF-ERR: could not message user")
    try:
        write_audit(AuditRecord(incident_id=ticket_id, user_id=user_id, redacted_message=safe_msg,
                                escalation_reasons=[reason[:500]], outcome=SYSTEM_ERROR,
                                reply_sent=reply is not None, duration_ms=_ms(t_start)))
        done.append("audit written")
    except Exception:  # noqa: BLE001
        log.exception("WF-ERR: could not write audit")
    try:
        if ticket_id:
            s = sessions.get(session_id, user_id=user_id)
            s.open_incident_id = ticket_id
            s.last_outcome = SYSTEM_ERROR
            sessions.save(s)
    except Exception:  # noqa: BLE001
        log.exception("WF-ERR: could not update session")

    trace.add("WF-ERR", "code", reason[:160], "; ".join(done), branch=SYSTEM_ERROR, duration_ms=_ms(t0))
    return _response(200, trace, t_start, outcome=SYSTEM_ERROR, ticket_id=ticket_id, reply=reply,
                     requires_human=True, error=reason)
