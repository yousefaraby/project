"""STUB Agent Service (Part 2). Returns a configurable fixed result.

Tests configure the module-level `stub` object; the real agent replaces process_incident later.
"""
from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field
from typing import Any

from app.agents.base import Trace
from app.services.data import register_reset
from app.services.messaging import ReplyContext, reply_idempotency_key, send_reply

HUMAN_OUTCOMES = {"escalated_to_human", "unresolved_handoff_L2", "action_failed"}


@dataclass
class StubAgent:
    outcome: str = "auto_resolved"
    reply_text: str = "Stub reply: please update your VPN client to 5.2 and reconnect."
    requires_human: bool | None = None  # None -> derived from outcome
    triage: dict[str, Any] = field(default_factory=lambda: {"category": "network", "severity": "medium"})
    findings: dict[str, Any] = field(default_factory=lambda: {"stub_finding": "vpn client outdated"})
    draft: str = "Draft: suggested reply for human review."
    injection_detected: bool = False
    delays: list[float] = field(default_factory=list)       # per-attempt delay (seconds)
    raise_on_attempts: set[int] = field(default_factory=set)
    invalid_on_attempts: set[int] = field(default_factory=set)
    extra: dict[str, Any] = field(default_factory=dict)     # merged into the result
    calls: list[dict[str, Any]] = field(default_factory=list)
    attempts: dict[str, int] = field(default_factory=dict)

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


stub = StubAgent()
register_reset(stub.reset)


async def process_incident(incident: dict[str, Any], session_ctx: dict[str, Any]) -> dict[str, Any]:
    s = stub
    key = incident["idempotency_key"]
    attempt = s.attempts[key] = s.attempts.get(key, 0) + 1
    s.calls.append({"attempt": attempt, "incident": copy.deepcopy(incident),
                    "session_ctx": copy.deepcopy(session_ctx)})

    if attempt in s.raise_on_attempts:
        raise RuntimeError("stub agent crashed")

    requires_human = s.requires_human if s.requires_human is not None else s.outcome in HUMAN_OUTCOMES
    reply_sent = False
    if s.outcome == "auto_resolved" and not requires_human:
        # The agent sends its own reply for auto_resolved (idempotent per request).
        send_reply(ReplyContext(incident["incident_id"], incident["user_id"], requires_human),
                   incident["incident_id"], incident["user_id"], s.reply_text,
                   idempotency_key=reply_idempotency_key(key))
        reply_sent = True

    delay = s.delays[attempt - 1] if attempt <= len(s.delays) else 0.0
    if delay:
        await asyncio.sleep(delay)

    if attempt in s.invalid_on_attempts:
        return {"outcome": "made_up_outcome", "reply_text": 42}

    trace = Trace()
    trace.add("stub_agent", "llm", incident["message"][:60], f"outcome={s.outcome}", branch=s.outcome)
    result = {
        "outcome": s.outcome,
        "reply_text": s.reply_text,
        "reply_sent": reply_sent,
        "requires_human": requires_human,
        "triage": copy.deepcopy(s.triage),
        "injection_detected": s.injection_detected,
        "findings": copy.deepcopy(s.findings),
        "draft": s.draft,
        "trace": trace.to_list(),
    }
    result.update(copy.deepcopy(s.extra))
    return result
