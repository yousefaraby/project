"""Thin UI and programmatic accessors without behavioral side-effects."""
from __future__ import annotations

from typing import Any

from app.controls import controls
from app.services.audit import get_audit_record_by_id, get_audit_records, list_audit_records
from app.services.data import reset_data
from app.services.itsm import Ticket, itsm
from app.services.messaging import read_alerts, read_outbox


def handle_request(*args: Any, **kwargs: Any) -> Any:
    from app.backend.pipeline import handle_request as _handle_request
    return _handle_request(*args, **kwargs)


def list_tickets() -> list[Ticket]:
    return itsm.list_tickets()


def get_ticket(ticket_id: str) -> Ticket:
    return itsm.get_ticket(ticket_id)


def list_audit(filters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    records = list_audit_records()
    if not filters:
        return records
    filtered = []
    for r in records:
        match = True
        for k, v in filters.items():
            if r.get(k) != v:
                match = False
                break
        if match:
            filtered.append(r)
    return filtered


def get_audit(incident_id: str) -> list[dict[str, Any]]:
    return get_audit_records(incident_id)


def get_audit_by_id(record_id: int) -> dict[str, Any] | None:
    return get_audit_record_by_id(record_id)


def list_alerts() -> list[dict[str, Any]]:
    return read_alerts()


def list_outbox() -> list[dict[str, Any]]:
    return read_outbox()


def list_review_queue() -> list[dict[str, Any]]:
    from app.backend.pipeline import review_queue
    return list(review_queue)


def run_scenario(case_id: str) -> dict[str, Any]:
    from app.services.scenarios import run_scenario as _run_scenario
    return _run_scenario(case_id)


def reset_rate_limit() -> None:
    from app.backend.pipeline import rate_limiter
    rate_limiter.reset()


def reset_all_data() -> None:
    reset_data()


def set_kill_switch(enabled: bool) -> bool:
    controls.kill_switch = bool(enabled)
    return controls.kill_switch


def set_fault(name: str, value: Any) -> None:
    if name == "kill_switch":
        controls.kill_switch = bool(value)
    elif name == "agent_service_fault":
        controls.set_agent_service_fault(str(value))
    elif name == "agent_fault":
        if isinstance(value, bool):
            controls.agent_fault = value
            controls.agent_service_fault = "exception" if value else "none"
        else:
            controls.set_agent_service_fault(str(value))
    elif name == "troubleshooter_behavior":
        controls.set_troubleshooter_behavior(value)
    elif name == "slow_delay_s":
        controls.slow_delay_s = float(value)
    else:
        controls.set_tool_mode(name, str(value))
