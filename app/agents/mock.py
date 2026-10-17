"""Deterministic rule-based mock agents. Swap for LLM-backed implementations of app.agents.base."""
from __future__ import annotations

import re
from typing import Any

# Category keyword sets. NOTE: the security set is deliberately narrow (no "hacked",
# "compromised", "leaked"...). The independent keyword scan is the safety net; this
# mimics an LLM that under-classifies some security incidents.
_CATEGORY_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("security", re.compile(r"\b(phishing|ransomware|malware|suspicious\s+email|edr\s+alert)\b", re.I)),
    ("network", re.compile(r"\b(vpn|wi-?fi|internet|network|ethernet|disconnect\w*|connection)\b", re.I)),
    ("account", re.compile(r"\b(password|locked|lockout|log\s?in|sign\s?in|account|mfa|credentials?)\b", re.I)),
    ("application", re.compile(r"\b(outlook|teams|excel|word|sharepoint|onedrive|app|application|software|"
                               r"error|crash(es|ed|ing)?)\b", re.I)),
    ("device", re.compile(r"\b(laptop|computer|pc|screen|keyboard|mouse|battery|charger|monitor|broken)\b", re.I)),
]
_TIE_ORDER = [c for c, _ in _CATEGORY_RULES]

_BASE_SEVERITY = {"security": "high", "network": "medium", "application": "medium",
                  "account": "low", "device": "low", "unknown": "low"}
_LEVELS = ["low", "medium", "high", "critical"]

_OUTAGE = re.compile(r"\b(everyone|all\s+users|whole\s+(office|company|team)|entire\s+(office|company|floor)|"
                     r"nobody\s+can|outage)\b", re.I)
_CRITICAL_SEC = re.compile(r"\b(ransomware|files?\s+(are\s+)?encrypted|data\s+breach)\b", re.I)
_URGENT = re.compile(r"\b(urgent|asap|can'?t\s+work|cannot\s+work|deadline)\b", re.I)

_APP_NAMES = re.compile(r"\b(outlook|teams|excel|word|sharepoint|onedrive|chrome|edge|zoom|sap)\b", re.I)
_DEVICE_SYMPTOMS = re.compile(r"\b(screen|display|battery|charg\w*|boot\w*|start\w*|turn\w*\s+on|power\w*|slow|"
                              r"keyboard|mouse|overheat\w*|hot|noise|fan|blue\s+screen|bsod|crash\w*|freez\w*|"
                              r"black|flicker\w*|cracked|wifi|sound|audio|camera)\b", re.I)
_DEVICE_ID = re.compile(r"\bLT-\d{3}\b", re.I)

_QUESTIONS = {
    "problem_description": "Could you describe what exactly isn't working and what you see on screen?",
    "symptoms": "Could you tell me what happens exactly (e.g. it won't turn on, the screen is black, it's very slow) and since when?",
    "application_name": "Which application shows the problem (e.g. Outlook, Teams, Excel)?",
}


def follow_up_question(missing_info: list[str]) -> str:
    parts = [_QUESTIONS.get(m, f"Could you provide more details about: {m}?") for m in missing_info]
    return " ".join(dict.fromkeys(parts))


class MockTriageAgent:
    """Keyword-rule triage. Implements app.agents.base.TriageAgent."""

    async def triage(self, message: str, context: dict[str, Any]) -> dict[str, Any]:
        text = message or ""
        scores = {cat: len(p.findall(text)) for cat, p in _CATEGORY_RULES}
        best = max(scores.values())
        category = "unknown" if best == 0 else min(
            (c for c, s in scores.items() if s == best), key=_TIE_ORDER.index)

        severity = _BASE_SEVERITY[category]
        if category == "security" and _CRITICAL_SEC.search(text):
            severity = "critical"
        elif _OUTAGE.search(text):
            severity = "critical" if category in ("network", "application") else "high"
        elif _URGENT.search(text):
            severity = _LEVELS[min(_LEVELS.index(severity) + 1, 2)]  # urgency caps at high

        missing: list[str] = []
        if category == "unknown":
            missing.append("problem_description")
        elif category == "device" and not _DEVICE_SYMPTOMS.search(text):
            missing.append("symptoms")
        elif category == "application" and not _APP_NAMES.search(text):
            missing.append("application_name")

        m = _DEVICE_ID.search(text)
        device = m.group(0).upper() if m else context.get("laptop_id")
        return {
            "category": category,
            "severity": severity,
            "security_flag": category == "security",
            "affected_user": context.get("user_id"),
            "affected_device": device,
            "summary": f"{category} issue: {' '.join(text.split())[:100]}",
            "missing_info": missing,
        }


# ---------------------------------------------------------------------------
# Step 3: Mock Planner
# ---------------------------------------------------------------------------

CATEGORY_WORKERS: dict[str, list[str]] = {
    "network": ["Network", "Device", "KB"],
    "account": ["Account", "KB"],
    "device": ["Device", "KB"],
    "application": ["Device", "KB"],
    "security": ["Account", "Device", "KB"],
    "unknown": ["KB"],
}

WORKER_TOOLS: dict[str, list[str]] = {
    "Network": ["check_network_status", "check_vpn_status"],
    "Account": ["check_account_status"],
    "Device": ["check_device_status"],
    "KB": ["search_it_knowledge"],
}


class MockPlanner:
    """Maps triage category to workers and proposed checks with short reasoning."""

    async def plan(self, triage: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        category = triage.get("category", "unknown").lower()
        workers = CATEGORY_WORKERS.get(category, ["KB"])

        tools: list[str] = []
        for w in workers:
            for t in WORKER_TOOLS.get(w, []):
                if t not in tools:
                    tools.append(t)

        reasoning = (
            f"Category '{category}' investigation: assign workers [{', '.join(workers)}] "
            f"to gather diagnostics via checks [{', '.join(tools)}]."
        )

        return {
            "category": category,
            "workers": list(workers),
            "tools": tools,
            "reasoning": reasoning,
        }


# ---------------------------------------------------------------------------
# Step 4: Workers
# ---------------------------------------------------------------------------

import asyncio
import time
from app.tools.it_tools import (
    check_account_status,
    check_device_status,
    check_network_status,
    check_vpn_status,
    search_it_knowledge,
)


class NetworkWorker:
    name: str = "Network"

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        t0 = time.perf_counter()
        user_id = context.get("user_id", "")
        timeout_s = task.get("timeout_s", 2.0)

        evidence: dict[str, Any] = {}
        findings: list[str] = []
        has_error = False

        # Concurrently probe network status and VPN status
        async def _call_tool(tool_fn, name):
            try:
                return await asyncio.wait_for(tool_fn(user_id), timeout=timeout_s)
            except asyncio.TimeoutError:
                return {"tool": name, "ok": False, "mode": "timeout", "data": None,
                        "error": f"{name} timed out after {timeout_s}s", "error_type": "timeout", "latency_ms": timeout_s * 1000}
            except Exception as e:
                return {"tool": name, "ok": False, "mode": "error", "data": None,
                        "error": str(e), "error_type": "error", "latency_ms": 0.0}

        net_res, vpn_res = await asyncio.gather(
            _call_tool(check_network_status, "check_network_status"),
            _call_tool(check_vpn_status, "check_vpn_status"),
        )

        for res in (net_res, vpn_res):
            tool = res["tool"]
            evidence[tool] = res
            if not res["ok"]:
                has_error = True
            elif res["data"]:
                data = res["data"]
                if tool == "check_vpn_status":
                    if data.get("drops_last_hour", 0) > 0:
                        findings.append(f"VPN dropped {data['drops_last_hour']}x in last hour (reason: {data.get('last_drop_reason')})")
                    if data.get("client_version") != data.get("latest_version"):
                        findings.append(f"VPN client outdated: {data.get('client_version')} (latest: {data.get('latest_version')})")
                    if data.get("gateway_status") != "healthy":
                        findings.append(f"VPN gateway: {data.get('gateway_status')}")
                elif tool == "check_network_status":
                    if data.get("gateway_status") != "healthy":
                        findings.append(f"Network gateway: {data.get('gateway_status')}")
                    if data.get("packet_loss_pct", 0) > 0:
                        findings.append(f"Network packet loss: {data.get('packet_loss_pct')}%")

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "worker": self.name,
            "status": "error" if has_error else "ok",
            "findings": findings,
            "evidence": evidence,
            "latency": latency,
        }


class AccountWorker:
    name: str = "Account"

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        t0 = time.perf_counter()
        user_id = context.get("user_id", "")
        timeout_s = task.get("timeout_s", 2.0)

        findings: list[str] = []
        evidence: dict[str, Any] = {}
        has_error = False

        try:
            res = await asyncio.wait_for(check_account_status(user_id), timeout=timeout_s)
        except asyncio.TimeoutError:
            res = {"tool": "check_account_status", "ok": False, "mode": "timeout", "data": None,
                   "error": f"check_account_status timed out after {timeout_s}s", "error_type": "timeout", "latency_ms": timeout_s * 1000}
        except Exception as e:
            res = {"tool": "check_account_status", "ok": False, "mode": "error", "data": None,
                   "error": str(e), "error_type": "error", "latency_ms": 0.0}

        evidence["check_account_status"] = res
        if not res["ok"]:
            has_error = True
        elif res["data"]:
            data = res["data"]
            if data.get("locked"):
                findings.append(f"Account locked after {data.get('failed_attempts')} failed attempts (auto-unlock: {data.get('auto_unlock_minutes')} min)")
            if data.get("suspicious_signins"):
                findings.append(f"Detected {len(data['suspicious_signins'])} suspicious sign-in event(s)")
            if data.get("recent_password_change") and not data["recent_password_change"].get("known_location", True):
                findings.append(f"Recent password change from unknown location: {data['recent_password_change'].get('location')}")

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "worker": self.name,
            "status": "error" if has_error else "ok",
            "findings": findings,
            "evidence": evidence,
            "latency": latency,
        }


class DeviceWorker:
    name: str = "Device"

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        t0 = time.perf_counter()
        user_id = context.get("user_id", "")
        timeout_s = task.get("timeout_s", 2.0)

        findings: list[str] = []
        evidence: dict[str, Any] = {}
        has_error = False

        try:
            res = await asyncio.wait_for(check_device_status(user_id), timeout=timeout_s)
        except asyncio.TimeoutError:
            res = {"tool": "check_device_status", "ok": False, "mode": "timeout", "data": None,
                   "error": f"check_device_status timed out after {timeout_s}s", "error_type": "timeout", "latency_ms": timeout_s * 1000}
        except Exception as e:
            res = {"tool": "check_device_status", "ok": False, "mode": "error", "data": None,
                   "error": str(e), "error_type": "error", "latency_ms": 0.0}

        evidence["check_device_status"] = res
        if not res["ok"]:
            has_error = True
        elif res["data"]:
            data = res["data"]
            if data.get("edr_alerts"):
                for alert in data["edr_alerts"]:
                    findings.append(f"EDR alert: {alert.get('name')} (severity: {alert.get('severity')})")
            if not data.get("compliant", True):
                findings.append("Device is non-compliant")
            if data.get("laptop_id"):
                findings.append(f"Laptop {data.get('laptop_id')} running {data.get('os')}")

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "worker": self.name,
            "status": "error" if has_error else "ok",
            "findings": findings,
            "evidence": evidence,
            "latency": latency,
        }


class KBWorker:
    name: str = "KB"

    async def run(self, task: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        t0 = time.perf_counter()
        query = task.get("query") or context.get("message", "")
        user_id = context.get("user_id")
        timeout_s = task.get("timeout_s", 2.0)

        findings: list[str] = []
        evidence: dict[str, Any] = {}
        has_error = False

        try:
            res = await asyncio.wait_for(search_it_knowledge(query, user_id=user_id), timeout=timeout_s)
        except asyncio.TimeoutError:
            res = {"tool": "search_it_knowledge", "ok": False, "mode": "timeout", "data": None,
                   "error": f"search_it_knowledge timed out after {timeout_s}s", "error_type": "timeout", "latency_ms": timeout_s * 1000}
        except Exception as e:
            res = {"tool": "search_it_knowledge", "ok": False, "mode": "error", "data": None,
                   "error": str(e), "error_type": "error", "latency_ms": 0.0}

        evidence["search_it_knowledge"] = res
        if not res["ok"]:
            has_error = True
        elif res["data"]:
            matches = res["data"].get("matches", [])
            if matches:
                for m in matches:
                    findings.append(f"KB match {m.get('id')}: {m.get('title')}")
            else:
                findings.append("No KB articles matched")

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "worker": self.name,
            "status": "error" if has_error else "ok",
            "findings": findings,
            "evidence": evidence,
            "latency": latency,
        }


# ---------------------------------------------------------------------------
# Step 5: Mock Troubleshooter & Evaluator
# ---------------------------------------------------------------------------

import re
from app.services import fixtures

_CREDENTIAL_REQ = re.compile(
    r"\b(what\s+is\s+(your|the|his|her|their)\s+password|give\s+me\s+(the\s+)?(password|secret|key|token))\b",
    re.I,
)
_UNSAFE_ADMIN = re.compile(
    r"\b(reset|change)\s+(your\s+|the\s+|his\s+|her\s+|user['’]?s\s+)?(password|credentials?)\b"
    r"|\b(disable|turn\s*off|bypass)\s+(mfa|2fa)\b"
    r"|\b(make|grant|elevate)\s+(local\s+|domain\s+)?(admin|privileges?)\b",
    re.I,
)
_CLAIM_ACTION_DONE = re.compile(
    r"\b(i\s+(have\s+)?(reset|unlocked|disabled|changed|modified|created|deleted|cleared|granted))\b"
    r"|\b(password\s+(has\s+been|was)\s+reset\s+by\s+me)\b",
    re.I,
)


class MockTroubleshooter:
    """Proposes diagnostic resolution draft with evidence references."""

    async def propose(
        self, findings: dict[str, Any], feedback: str | None, context: dict[str, Any]
    ) -> dict[str, Any]:
        user_id = context.get("user_id", "")
        behavior = fixtures.troubleshooter_behavior(user_id)

        # 1. Hallucinate always: every attempt includes an unsupported claim
        if behavior == "hallucinate_always":
            return {
                "text": "I have reset your password and disabled MFA for your account.",
                "claims": [
                    {
                        "claim": "I reset your password to a temporary password.",
                        "evidence_refs": ["unsupported_action_reset"],
                    },
                    {
                        "claim": "I disabled MFA on your device.",
                        "evidence_refs": ["unsupported_action_mfa"],
                    },
                ],
            }

        # 2. Hallucinate once: attempt 1 includes unsupported claim; attempt 2+ follows critique
        if behavior == "hallucinate_once" and not feedback:
            return {
                "text": "I have unlocked your account and reset your password for you.",
                "claims": [
                    {
                        "claim": "I reset your password and unlocked your account.",
                        "evidence_refs": ["unsupported_action_reset"],
                    }
                ],
            }

        # 3. Verified proposal backed by findings
        evidence_dict = findings.get("evidence", {})
        claims = []
        text_parts = []

        # Check VPN
        vpn_evidence = evidence_dict.get("Network", {}).get("check_vpn_status", {})
        if vpn_evidence.get("ok") and vpn_evidence.get("data"):
            v_data = vpn_evidence["data"]
            if v_data.get("client_version") != v_data.get("latest_version"):
                claims.append({
                    "claim": f"VPN client {v_data.get('client_version')} is outdated compared to latest {v_data.get('latest_version')}.",
                    "evidence_refs": ["check_vpn_status"],
                })
                text_parts.append(
                    f"Your VPN client version ({v_data.get('client_version')}) is outdated. "
                    f"Please update to version {v_data.get('latest_version')} from the Software Center and reconnect."
                )

        # Check Account
        acc_evidence = evidence_dict.get("Account", {}).get("check_account_status", {})
        if acc_evidence.get("ok") and acc_evidence.get("data"):
            a_data = acc_evidence["data"]
            if a_data.get("locked"):
                claims.append({
                    "claim": f"Account is locked after {a_data.get('failed_attempts')} failed attempts; auto-unlocks in {a_data.get('auto_unlock_minutes')} min.",
                    "evidence_refs": ["check_account_status"],
                })
                text_parts.append(
                    f"Your account is currently locked due to failed sign-in attempts. "
                    f"It will unlock automatically in {a_data.get('auto_unlock_minutes')} minutes."
                )

        # Check KB
        kb_evidence = evidence_dict.get("KB", {}).get("search_it_knowledge", {})
        if kb_evidence.get("ok") and kb_evidence.get("data"):
            kb_matches = kb_evidence["data"].get("matches", [])
            if kb_matches:
                best = kb_matches[0]
                claims.append({
                    "claim": f"Knowledge base article {best['id']} applies: {best['title']}.",
                    "evidence_refs": ["search_it_knowledge"],
                })
                if best.get("resolution_steps"):
                    text_parts.append("Resolution: " + " ".join(best["resolution_steps"]))

        # Fallback if no specific recommendations could be formed from evidence
        if not claims:
            claims.append({
                "claim": "Diagnostic checks completed without matched automated resolution.",
                "evidence_refs": ["search_it_knowledge"],
            })
            text_parts.append("Diagnostic checks ran, but no automated resolution was found in the knowledge base.")

        return {
            "text": " ".join(text_parts),
            "claims": claims,
        }


class Evaluator:
    """Rule layer + support check for troubleshooter drafts."""

    async def evaluate(self, proposal: dict[str, Any], findings: dict[str, Any]) -> dict[str, Any]:
        text = proposal.get("text", "")
        claims = proposal.get("claims", [])
        issues: list[str] = []

        # 1. Rule layer
        if _CREDENTIAL_REQ.search(text):
            issues.append("Draft requests user credentials or passwords")
        if _UNSAFE_ADMIN.search(text):
            issues.append("Draft proposes unsafe admin action (password reset, MFA disable, privilege grant)")
        if _CLAIM_ACTION_DONE.search(text):
            issues.append("Draft claims an action was executed (the agent cannot execute changes)")

        for c in claims:
            c_text = c.get("claim", "")
            if _CREDENTIAL_REQ.search(c_text):
                issues.append(f"Claim requests credentials: '{c_text}'")
            if _UNSAFE_ADMIN.search(c_text):
                issues.append(f"Claim proposes unsafe admin action: '{c_text}'")
            if _CLAIM_ACTION_DONE.search(c_text):
                issues.append(f"Claim asserts action was done: '{c_text}'")

        # 2. Support check
        evidence_dict = findings.get("evidence", {})
        # Collect all valid tool names in findings
        valid_tools: set[str] = set()
        for worker_name, tools in evidence_dict.items():
            valid_tools.update(tools.keys())
        # Also include any direct keys in findings
        valid_tools.update(findings.keys())

        # Collect failed tools
        tool_errors = findings.get("tool_errors", [])
        failed_tools = {e["tool"] for e in tool_errors if isinstance(e, dict) and "tool" in e}

        for c in claims:
            refs = c.get("evidence_refs", [])
            if not refs:
                issues.append(f"Claim '{c.get('claim')}' lacks evidence_refs")
            for ref in refs:
                if ref not in valid_tools:
                    issues.append(f"Claim relies on non-existent evidence reference: '{ref}'")
                elif ref in failed_tools:
                    issues.append(f"Claim relies on failed tool '{ref}'")

        if issues:
            critique = "Critique: " + "; ".join(issues) + ". Remove unsupported claims and rely strictly on verified tool evidence."
            return {"approved": False, "issues": issues, "critique": critique}

        return {"approved": True, "issues": [], "critique": ""}


