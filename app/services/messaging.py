"""Mock outbound messaging: user replies (outbox) and internal notifications (alerts)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import alerts_path, outbox_path

NOTIFY_CHANNELS: tuple[str, ...] = ("SOC", "on-call", "Security", "IT-ops")

# Fixed, pre-approved user-facing texts. Only {ticket_id} and {eta} may be filled in,
# so these can never carry agent-generated content.
TEMPLATES: dict[str, str] = {
    "holding": ("Thanks for reporting this. Your request ({ticket_id}) has been passed to a "
                "specialist for review and you will hear back soon. Please don't take any further "
                "action on it in the meantime."),
    "l2_handoff": ("Your ticket {ticket_id} has been assigned to our Level 2 support team. "
                   "Expected response time: {eta}."),
    "guardrail_refusal": ("Sorry, I can't help with that request. If you are experiencing an IT "
                          "problem, please describe what is happening and I'll look into it."),
    "human_follow_up": ("We couldn't process your request automatically. A member of the IT team "
                        "will follow up on ticket {ticket_id} shortly."),
}
_TEMPLATE_PARAMS = {"eta"}

_sent_keys: set[str] = set()


@dataclass
class ReplyContext:
    incident_id: str
    user_id: str
    requires_human: bool


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _requires_human(ctx: Any) -> bool:
    """Fail closed: a ctx without a requires_human value is treated as requiring a human."""
    if isinstance(ctx, dict):
        val = ctx.get("requires_human", None)
    else:
        val = getattr(ctx, "requires_human", None)
    return True if val is None else bool(val)


def reply_idempotency_key(idempotency_key: str) -> str:
    """Key for the single user-facing reply of one request (shared by agent and backend)."""
    return f"{idempotency_key}:reply"


def _deliver(ticket_id: str, user_id: str, text: str, idempotency_key: str | None,
             kind: str) -> dict[str, Any]:
    if idempotency_key and idempotency_key in _sent_keys:
        return {"duplicate": True, "idempotency_key": idempotency_key,
                "ticket_id": ticket_id, "user_id": user_id, "text": text, "kind": kind}
    record = {"ts": _now(), "ticket_id": ticket_id, "user_id": user_id, "text": text,
              "kind": kind, "idempotency_key": idempotency_key}
    _append_jsonl(outbox_path(), record)
    if idempotency_key:
        _sent_keys.add(idempotency_key)
    return record


def send_reply(ctx: Any, ticket_id: str, user_id: str, text: str,
               idempotency_key: str | None = None) -> dict[str, Any]:
    """Free-text reply. Refuses when the incident requires a human.

    If idempotency_key was already delivered, nothing is written and a record with
    duplicate=True is returned.
    """
    if _requires_human(ctx):
        raise PermissionError("send_reply refused: requires_human is set (or unknown) for this incident")
    return _deliver(ticket_id, user_id, text, idempotency_key, "reply")


def send_template(name: str, ticket_id: str, user_id: str, idempotency_key: str | None = None,
                  **params: str) -> dict[str, Any]:
    """Send a fixed, pre-approved template. Allowed even when requires_human is True."""
    if name not in TEMPLATES:
        raise ValueError(f"unknown template: {name}")
    bad = set(params) - _TEMPLATE_PARAMS
    if bad:
        raise ValueError(f"template params not allowed: {sorted(bad)}")
    text = TEMPLATES[name].format(ticket_id=ticket_id, eta=params.get("eta", ""))
    return _deliver(ticket_id, user_id, text, idempotency_key, f"template:{name}")


def clear_sent_keys() -> None:
    _sent_keys.clear()


def notify(channel: str, incident_id: str, message: str, severity: str = "medium") -> dict[str, Any]:
    if channel not in NOTIFY_CHANNELS:
        raise ValueError(f"unknown notify channel: {channel}")
    record = {"ts": _now(), "channel": channel, "incident_id": incident_id,
              "severity": severity, "message": message}
    _append_jsonl(alerts_path(), record)
    return record


def read_outbox() -> list[dict[str, Any]]:
    return _read_jsonl(outbox_path())


def read_alerts() -> list[dict[str, Any]]:
    return _read_jsonl(alerts_path())
