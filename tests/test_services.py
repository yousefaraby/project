import pytest

from app.services.itsm import TicketStatus, itsm
from app.services.messaging import ReplyContext, notify, read_alerts, read_outbox, send_reply
from app.services.session import sessions


# ---- send_reply -------------------------------------------------------------

def test_send_reply_refuses_when_requires_human():
    ctx = ReplyContext(incident_id="INC-0001", user_id="emp_005", requires_human=True)
    with pytest.raises(PermissionError):
        send_reply(ctx, "INC-0001", "emp_005", "All fixed!")
    assert read_outbox() == []


def test_send_reply_refuses_dict_ctx_and_missing_flag():
    with pytest.raises(PermissionError):
        send_reply({"requires_human": True}, "INC-0001", "emp_005", "x")
    with pytest.raises(PermissionError):  # fail closed
        send_reply({}, "INC-0001", "emp_005", "x")
    with pytest.raises(PermissionError):
        send_reply(object(), "INC-0001", "emp_005", "x")
    assert read_outbox() == []


def test_send_reply_writes_outbox_when_allowed():
    ctx = ReplyContext(incident_id="INC-0001", user_id="emp_001", requires_human=False)
    rec = send_reply(ctx, "INC-0001", "emp_001", "Please update your VPN client.")
    out = read_outbox()
    assert len(out) == 1 and out[0]["text"] == rec["text"] and "ts" in out[0]


# ---- notify -----------------------------------------------------------------

@pytest.mark.parametrize("channel", ["SOC", "on-call", "Security", "IT-ops"])
def test_notify_appends_alert(channel):
    notify(channel, "INC-0002", "EDR alert on LT-005", severity="critical")
    alerts = read_alerts()
    assert alerts[-1]["channel"] == channel and alerts[-1]["ts"]


def test_notify_unknown_channel():
    with pytest.raises(ValueError):
        notify("Slack", "INC-1", "x")


# ---- ITSM -------------------------------------------------------------------

def test_itsm_lifecycle():
    t = itsm.create_ticket("emp_001", "VPN drops", severity="medium", category="network")
    assert t.ticket_id == "INC-0001" and t.status == TicketStatus.OPEN
    itsm.append_to_ticket(t.ticket_id, "still dropping")
    itsm.add_internal_note(t.ticket_id, "client 4.1 outdated")
    itsm.tag_ticket(t.ticket_id, "vpn", "kb:KB-VPN-001", "vpn")
    itsm.assign_ticket(t.ticket_id, "L2-Network")
    itsm.update_ticket(t.ticket_id, status="Assigned L2")
    itsm.set_needs_manual(t.ticket_id)
    itsm.set_flagged(t.ticket_id)
    t = itsm.get_ticket(t.ticket_id)
    assert t.status == TicketStatus.ASSIGNED_L2 and t.assignee == "L2-Network"
    assert t.needs_manual and t.flagged
    assert t.tags == ["vpn", "kb:KB-VPN-001"]
    assert len(t.comments) == 1 and len(t.internal_notes) == 1
    assert [h["event"] for h in t.history][0] == "created"


@pytest.mark.parametrize("status", [s.value for s in TicketStatus])
def test_itsm_all_statuses(status):
    t = itsm.create_ticket("emp_007", "x")
    assert itsm.update_ticket(t.ticket_id, status=status).status.value == status


def test_itsm_rejects_bad_update():
    t = itsm.create_ticket("emp_007", "x")
    with pytest.raises(ValueError):
        itsm.update_ticket(t.ticket_id, user_id="emp_001")
    with pytest.raises(ValueError):
        itsm.update_ticket(t.ticket_id, status="Exploded")
    with pytest.raises(KeyError):
        itsm.get_ticket("INC-9999")


# ---- sessions ---------------------------------------------------------------

def test_session_store():
    s = sessions.get("emp_001")
    assert s.history == [] and s.open_incident_id is None
    sessions.append_history("emp_001", "user", "vpn down")
    sessions.set_open_incident("emp_001", "INC-0001")
    s = sessions.get("emp_001")
    assert s.open_incident_id == "INC-0001" and s.history[0]["text"] == "vpn down"
    # get() returns a copy
    s.history.append({"role": "x"})
    assert len(sessions.get("emp_001").history) == 1
    sessions.save(s)
    assert len(sessions.get("emp_001").history) == 2
