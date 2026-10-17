"""In-memory mock ITSM (ticketing) service."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TicketStatus(str, Enum):
    OPEN = "Open"
    PENDING_USER_CONFIRMATION = "Pending user confirmation"
    WAITING_FOR_USER = "Waiting for user"
    ASSIGNED_L2 = "Assigned L2"
    CLOSED = "Closed"


class Ticket(BaseModel):
    ticket_id: str
    user_id: str
    summary: str
    description: str = ""
    status: TicketStatus = TicketStatus.OPEN
    severity: str = "medium"
    category: str | None = None
    assignee: str | None = None
    needs_manual: bool = False  # NEEDS-MANUAL flag
    flagged: bool = False
    tags: list[str] = Field(default_factory=list)
    comments: list[dict[str, Any]] = Field(default_factory=list)       # user-visible thread
    internal_notes: list[dict[str, Any]] = Field(default_factory=list)  # IT-only
    history: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = Field(default_factory=_now)
    updated_at: str = Field(default_factory=_now)


_UPDATABLE = {"status", "severity", "category", "needs_manual", "flagged", "summary"}


class ITSM:
    def __init__(self) -> None:
        self.tickets: dict[str, Ticket] = {}
        self._seq = 0

    def reset(self) -> None:
        self.tickets.clear()
        self._seq = 0

    def _get(self, ticket_id: str) -> Ticket:
        if ticket_id not in self.tickets:
            raise KeyError(f"unknown ticket: {ticket_id}")
        return self.tickets[ticket_id]

    def _event(self, t: Ticket, event: str, **details: Any) -> None:
        t.updated_at = _now()
        t.history.append({"ts": t.updated_at, "event": event, **details})

    def create_ticket(self, user_id: str, summary: str, description: str = "",
                      severity: str = "medium", category: str | None = None,
                      ticket_id: str | None = None) -> Ticket:
        self._seq += 1
        tid = ticket_id or f"INC-{self._seq:04d}"
        t = Ticket(ticket_id=tid, user_id=user_id, summary=summary,
                   description=description, severity=severity, category=category)
        self.tickets[t.ticket_id] = t
        self._event(t, "created")
        return t

    def get_ticket(self, ticket_id: str) -> Ticket:
        return self._get(ticket_id)

    def list_tickets(self) -> list[Ticket]:
        return list(self.tickets.values())

    def update_ticket(self, ticket_id: str, **fields: Any) -> Ticket:
        t = self._get(ticket_id)
        bad = set(fields) - _UPDATABLE
        if bad:
            raise ValueError(f"fields not updatable: {sorted(bad)}")
        if "status" in fields:
            fields["status"] = TicketStatus(fields["status"])
        for k, v in fields.items():
            setattr(t, k, v)
        self._event(t, "updated", fields={k: (v.value if isinstance(v, Enum) else v)
                                          for k, v in fields.items()})
        return t

    def append_to_ticket(self, ticket_id: str, text: str, author: str = "user") -> Ticket:
        t = self._get(ticket_id)
        t.comments.append({"ts": _now(), "author": author, "text": text})
        self._event(t, "comment_added", author=author)
        return t

    def add_internal_note(self, ticket_id: str, note: str, author: str = "agent") -> Ticket:
        t = self._get(ticket_id)
        t.internal_notes.append({"ts": _now(), "author": author, "note": note})
        self._event(t, "internal_note_added", author=author)
        return t

    def assign_ticket(self, ticket_id: str, assignee: str) -> Ticket:
        t = self._get(ticket_id)
        t.assignee = assignee
        self._event(t, "assigned", assignee=assignee)
        return t

    def tag_ticket(self, ticket_id: str, *tags: str) -> Ticket:
        t = self._get(ticket_id)
        for tag in tags:
            if tag not in t.tags:
                t.tags.append(tag)
        self._event(t, "tagged", tags=list(tags))
        return t

    def set_needs_manual(self, ticket_id: str, value: bool = True) -> Ticket:
        return self.update_ticket(ticket_id, needs_manual=value)

    def set_flagged(self, ticket_id: str, value: bool = True) -> Ticket:
        return self.update_ticket(ticket_id, flagged=value)


itsm = ITSM()
