"""Agent response contract + validation."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

Outcome = Literal[
    "auto_resolved",
    "needs_more_info",
    "escalated_to_human",
    "unresolved_handoff_L2",
    "blocked_by_guardrail",
    "action_failed",
]
OUTCOMES: tuple[str, ...] = Outcome.__args__  # type: ignore[attr-defined]
SYSTEM_ERROR = "system_error"

# Outcomes where the agent itself talks to the user with free text.
_FREE_TEXT_OUTCOMES = {"auto_resolved", "needs_more_info"}


class AgentResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    outcome: Outcome
    reply_text: str = ""
    reply_sent: bool = False
    requires_human: bool = False
    triage: dict[str, Any] = Field(default_factory=dict)
    kw_flag: bool = False
    injection_detected: bool = False
    escalation_reasons: list[str] = Field(default_factory=list)
    plan: dict[str, Any] = Field(default_factory=dict)
    findings: dict[str, Any] = Field(default_factory=dict)
    tool_results: list[dict[str, Any]] = Field(default_factory=list)
    tool_errors: list[dict[str, Any]] = Field(default_factory=list)
    eval_attempts: int = 0
    eval_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    draft: str = ""
    notes: str = ""
    eta: str | None = None
    trace: list[dict[str, Any]] = Field(default_factory=list)


class InvalidAgentResponse(Exception):
    pass


def is_critical_or_security(triage: dict[str, Any]) -> bool:
    return (str(triage.get("severity", "")).lower() == "critical"
            or str(triage.get("category", "")).lower() == "security")


def validate_agent_result(raw: Any) -> AgentResult:
    if not isinstance(raw, dict):
        raise InvalidAgentResponse(f"response is not a dict: {type(raw).__name__}")
    try:
        result = AgentResult.model_validate(raw)
    except ValidationError as e:
        raise InvalidAgentResponse(f"schema invalid: {e.errors()[0].get('msg')}") from e

    # Consistency / safety rules (defense in depth; the agent should already respect these).
    if result.outcome in _FREE_TEXT_OUTCOMES and result.requires_human:
        raise InvalidAgentResponse(f"{result.outcome} is not allowed when requires_human=True")
    if result.outcome == "auto_resolved" and is_critical_or_security(result.triage):
        raise InvalidAgentResponse("critical/security incident cannot be auto_resolved")
    if result.outcome == "needs_more_info" and not result.reply_text.strip():
        raise InvalidAgentResponse("needs_more_info requires a follow-up question in reply_text")
    if result.outcome == "auto_resolved" and not (result.reply_sent or result.reply_text.strip()):
        raise InvalidAgentResponse("auto_resolved without a reply")
    return result
