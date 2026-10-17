"""Step 2: deterministic routing rules (no AI)."""
from __future__ import annotations

from typing import Any

ROUTING_REASONS: tuple[str, ...] = ("critical_severity", "security_category", "security_flag", "keyword_hit")
_SECURITY_REASONS = {"security_category", "security_flag", "keyword_hit"}


def decide_route(triage: dict[str, Any], kw_flag: bool) -> list[str]:
    """Returns escalation reasons in a fixed order; empty list = no human required."""
    reasons: list[str] = []
    if str(triage.get("severity", "")).lower() == "critical":
        reasons.append("critical_severity")
    if str(triage.get("category", "")).lower() == "security":
        reasons.append("security_category")
    if triage.get("security_flag"):
        reasons.append("security_flag")
    if kw_flag:
        reasons.append("keyword_hit")
    return reasons


def alert_channel(reasons: list[str]) -> str | None:
    """SOC for anything security-related, on-call for non-security critical, None if no reasons."""
    if not reasons:
        return None
    return "SOC" if _SECURITY_REASONS & set(reasons) else "on-call"
