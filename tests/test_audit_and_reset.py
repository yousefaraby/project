import pytest

from app.config import alerts_path, outbox_path
from app.controls import controls
from app.services.audit import (
    REDACTED, AuditRecord, get_audit_records, list_audit_records, redact, write_audit,
)
from app.services.data import reset_data
from app.services.itsm import itsm
from app.services.messaging import ReplyContext, notify, send_reply
from app.services.session import sessions


# ---- redaction --------------------------------------------------------------

@pytest.mark.parametrize("text,secret", [
    ("my password is Hunter2!", "Hunter2!"),
    ("password: S3cret#99", "S3cret#99"),
    ("pwd=abc123xyz", "abc123xyz"),
    ("the verification code is 482913", "482913"),
    ("MFA code: 55 21 90", "55 21 90"),
    ("I got 7731042 by sms", "7731042"),
    ("Authorization: Bearer abc.def-ghi_jkl", "abc.def-ghi_jkl"),
    ("token=ghp_ABCdef1234567890", "ghp_ABCdef1234567890"),
    ("key sk-proj-AAAAbbbbCCCCdddd", "sk-proj-AAAAbbbbCCCCdddd"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part-1", "eyJhbGciOiJIUzI1NiJ9"),
    ("api_key: 9f8e7d6c5b4a", "9f8e7d6c5b4a"),
    ("blob a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7"),
])
def test_redact_removes_secrets(text, secret):
    out = redact(text)
    assert secret not in out and REDACTED in out


@pytest.mark.parametrize("text", [
    "My VPN keeps dropping on laptop LT-001",
    "Outlook shows an unknown error since 2026",
    "account locked after 5 attempts",
])
def test_redact_keeps_normal_text(text):
    assert redact(text) == text


def test_redact_empty():
    assert redact("") == "" and redact(None) == ""


# ---- audit ------------------------------------------------------------------

def _record(**kw):
    base = dict(
        incident_id="INC-0001", user_id="emp_001",
        redacted_message="vpn drops, my password is hunter2",
        triage={"category": "network", "severity": "medium"},
        kw_flag=False, escalation_reasons=[],
        plan={"workers": ["vpn", "network", "kb"]},
        tool_results=[{"tool": "check_vpn_status", "ok": True}],
        tool_errors=[], eval_attempts=1,
        eval_verdicts=[{"attempt": 1, "verdict": "pass"}],
        outcome="auto_resolved", reply_sent=True, duration_ms=123.4,
    )
    base.update(kw)
    return AuditRecord(**base)


def test_audit_write_and_read_roundtrip():
    rid = write_audit(_record())
    assert rid == 1
    recs = get_audit_records("INC-0001")
    assert len(recs) == 1
    r = recs[0]
    assert r["triage"]["category"] == "network"
    assert r["plan"]["workers"] == ["vpn", "network", "kb"]
    assert r["eval_verdicts"][0]["verdict"] == "pass"
    assert r["reply_sent"] is True and r["kw_flag"] is False
    assert r["outcome"] == "auto_resolved" and r["duration_ms"] == 123.4
    for field in AuditRecord.model_fields:
        assert field in r


def test_audit_redacts_on_write():
    write_audit(_record())
    msg = get_audit_records("INC-0001")[0]["redacted_message"]
    assert "hunter2" not in msg and REDACTED in msg


def test_audit_multiple_records_per_incident_and_listing():
    write_audit(_record())
    write_audit(_record(outcome="needs_more_info", reply_sent=False))
    write_audit(_record(incident_id="INC-0002", user_id="emp_005", outcome="escalated_to_human"))
    assert [r["outcome"] for r in get_audit_records("INC-0001")] == ["auto_resolved", "needs_more_info"]
    assert len(list_audit_records()) == 3


# ---- reset_data -------------------------------------------------------------

def test_reset_data_clears_everything():
    itsm.create_ticket("emp_001", "VPN")
    sessions.set_open_incident("emp_001", "INC-0001")
    send_reply(ReplyContext("INC-0001", "emp_001", False), "INC-0001", "emp_001", "hi")
    notify("SOC", "INC-0001", "x")
    write_audit(_record())
    controls.kill_switch = True
    controls.agent_fault = True
    controls.set_tool_mode("check_vpn_status", "error")
    controls.set_troubleshooter_behavior("hallucinate_always")

    reset_data()

    assert itsm.list_tickets() == []
    assert len(sessions) == 0
    assert not outbox_path().exists() and not alerts_path().exists()
    assert list_audit_records() == []
    assert controls.kill_switch is False and controls.agent_fault is False
    assert controls.tool_modes == {} and controls.troubleshooter_behavior is None
    # ticket numbering and audit ids restart
    assert itsm.create_ticket("emp_001", "x").ticket_id == "INC-0001"
    assert write_audit(_record()) == 1
