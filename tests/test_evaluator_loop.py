import asyncio
import pytest

from app.agent_service.service import process_incident
from app.backend.pipeline import handle_request
from app.controls import controls
from app.services.audit import get_audit_records
from app.services.itsm import TicketStatus, itsm
from app.services.messaging import read_alerts, read_outbox, send_reply


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. Loop Approves on Attempt 1
# ---------------------------------------------------------------------------

def test_loop_approves_on_attempt_1():
    # emp_001: VPN drops, old client 4.1. Clean "ok" behavior.
    incident = {
        "incident_id": "INC-0501",
        "user_id": "emp_001",
        "message": "VPN keeps dropping on my laptop with auth timeout",
        "idempotency_key": "INC-0501:msg1",
    }
    res = run(process_incident(incident, {}))

    assert res["outcome"] == "auto_resolved"
    assert res["eval_attempts"] == 1
    assert len(res["eval_verdicts"]) == 1
    assert res["eval_verdicts"][0]["approved"] is True
    assert res["reply_sent"] is True
    assert "5.2" in res["reply_text"]

    # Trace shows attempt 1 approval
    trace_steps = [t["step"] for t in res["trace"]]
    assert "troubleshooter_attempt_1" in trace_steps
    assert "evaluator_verdict_1" in trace_steps
    assert "troubleshooter_attempt_2" not in trace_steps


# ---------------------------------------------------------------------------
# 2. Rejects then Approves on Attempt 2 (emp_002)
# ---------------------------------------------------------------------------

def test_rejects_then_approves_on_attempt_2_emp_002():
    # emp_002: account locked. Configure hallucinate_once behavior.
    controls.set_troubleshooter_behavior("hallucinate_once")

    incident = {
        "incident_id": "INC-0502",
        "user_id": "emp_002",
        "message": "My account is locked out after failed login attempts",
        "idempotency_key": "INC-0502:msg1",
    }
    res = run(process_incident(incident, {}))

    assert res["outcome"] == "auto_resolved"
    assert res["eval_attempts"] == 2
    assert len(res["eval_verdicts"]) == 2

    # Attempt 1 was rejected
    assert res["eval_verdicts"][0]["attempt"] == 1
    assert res["eval_verdicts"][0]["approved"] is False
    assert len(res["eval_verdicts"][0]["issues"]) > 0

    # Attempt 2 was approved
    assert res["eval_verdicts"][1]["attempt"] == 2
    assert res["eval_verdicts"][1]["approved"] is True
    assert "30 minutes" in res["reply_text"]

    # Trace verifies both attempts logged
    trace_steps = [t["step"] for t in res["trace"]]
    assert "troubleshooter_attempt_1" in trace_steps
    assert "evaluator_verdict_1" in trace_steps
    assert "troubleshooter_attempt_2" in trace_steps
    assert "evaluator_verdict_2" in trace_steps


# ---------------------------------------------------------------------------
# 3. Exhausts After 3 Attempts (emp_003)
# ---------------------------------------------------------------------------

def test_exhausts_after_3_attempts_emp_003():
    # emp_003: Outlook unknown error. Configure hallucinate_always.
    controls.set_troubleshooter_behavior("hallucinate_always")

    incident = {
        "incident_id": "INC-0503",
        "user_id": "emp_003",
        "message": "Outlook error code when opening",
        "idempotency_key": "INC-0503:msg1",
    }
    res = run(process_incident(incident, {}))

    # All 3 attempts rejected -> handoff to L2
    assert res["outcome"] == "unresolved_handoff_L2"
    assert res["eval_attempts"] == 3
    assert len(res["eval_verdicts"]) == 3
    assert all(v["approved"] is False for v in res["eval_verdicts"])

    # Trace shows all 3 attempts
    trace_steps = [t["step"] for t in res["trace"]]
    assert "troubleshooter_attempt_1" in trace_steps
    assert "troubleshooter_attempt_2" in trace_steps
    assert "troubleshooter_attempt_3" in trace_steps
    assert "evaluator_verdict_3" in trace_steps


# ---------------------------------------------------------------------------
# 4. HARD RULE: requires_human forces escalated_to_human
# ---------------------------------------------------------------------------

def test_requires_human_forces_escalated_to_human_when_evaluator_approved():
    # emp_005 has EDR alert and suspicious signins -> requires_human = True
    incident = {
        "incident_id": "INC-0505",
        "user_id": "emp_005",
        "message": "EDR alert and malware detected on my laptop LT-005",
        "idempotency_key": "INC-0505:msg1",
    }
    res = run(process_incident(incident, {}))

    # Even though evaluator approved the draft, outcome MUST be escalated_to_human
    assert res["outcome"] == "escalated_to_human"
    assert res["requires_human"] is True
    assert res["eval_verdicts"][-1]["approved"] is True
    assert res["reply_sent"] is False  # send_reply was NOT called
    assert res["draft"] != ""  # Draft is saved for human review

    # Trace records the hard rule override
    assert any(t["step"] == "hard_rule_override" for t in res["trace"])


def test_requires_human_forces_escalated_to_human_when_evidence_insufficient():
    # emp_004: network status times out. We also set check_vpn_status to error.
    controls.set_tool_mode("check_vpn_status", "error")

    # Add security keyword to trigger requires_human = True
    incident = {
        "incident_id": "INC-0506",
        "user_id": "emp_004",
        "message": "I think I was hacked and my VPN connection drops",
        "idempotency_key": "INC-0506:msg1",
    }
    res = run(process_incident(incident, {}))

    # Critical tools failed AND requires_human is True:
    # Must be escalated_to_human, NOT unresolved_handoff_L2!
    assert res["outcome"] == "escalated_to_human"
    assert res["requires_human"] is True
    assert any(t["step"] == "hard_rule_override" for t in res["trace"])


# ---------------------------------------------------------------------------
# 5. send_reply NEVER Called for requires_human
# ---------------------------------------------------------------------------

def test_send_reply_never_called_for_requires_human():
    # Run through full backend pipeline with real process_incident
    res = run(handle_request(
        user_id="emp_005",
        message="Suspicious malware detected on LT-005",
        session_id="session_sec",
        authorization="Bearer test-token-emp_005",
    ))

    assert res["outcome"] == "escalated_to_human"
    assert res["requires_human"] is True

    # Outbox only contains the fixed holding template, NEVER agent free text
    outbox = read_outbox()
    assert len(outbox) == 1
    assert "passed to a specialist for review" in outbox[0]["text"]
    assert outbox[0]["kind"] == "template:holding"

    # Ticket internal note contains the draft for review
    t = itsm.get_ticket(res["ticket_id"])
    notes = [n["note"] for n in t.internal_notes]
    assert any("[HUMAN REVIEW QUEUE]" in n for n in notes)


# ---------------------------------------------------------------------------
# 6. Action Failure -> action_failed
# ---------------------------------------------------------------------------

def test_action_failure_results_in_action_failed(monkeypatch):
    # For an auto-resolvable case (emp_001), simulate failure in update_ticket
    def mock_update(*args, **kwargs):
        raise RuntimeError("ITSM database connection lost")

    monkeypatch.setattr(itsm, "update_ticket", mock_update)

    incident = {
        "incident_id": "INC-0507",
        "user_id": "emp_001",
        "message": "VPN keeps dropping with auth timeout",
        "idempotency_key": "INC-0507:msg1",
    }
    res = run(process_incident(incident, {}))

    assert res["outcome"] == "action_failed"
    assert res["reply_sent"] is False
    assert any(t["step"] == "action_tools" and t["branch"] == "action_failed" for t in res["trace"])


# ---------------------------------------------------------------------------
# 7. End-to-End Execution with Real process_incident
# ---------------------------------------------------------------------------

def test_end_to_end_auto_resolution():
    res = run(handle_request(
        user_id="emp_001",
        message="My VPN drops repeatedly on laptop LT-001",
        session_id="session_e2e_1",
        authorization="Bearer test-token-emp_001",
    ))

    assert res["status"] == 200
    assert res["outcome"] == "auto_resolved"
    assert res["ticket_id"] is not None

    ticket = itsm.get_ticket(res["ticket_id"])
    assert ticket.status == TicketStatus.PENDING_USER_CONFIRMATION

    # Audit written in SQLite
    audits = get_audit_records(res["ticket_id"])
    assert len(audits) == 1
    assert audits[0]["outcome"] == "auto_resolved"
    assert audits[0]["reply_sent"] is True
    assert audits[0]["eval_attempts"] == 1
