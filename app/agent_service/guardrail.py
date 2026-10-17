"""Step 0: input guardrail (plain code, runs before any AI or tool).

Blocks prompt injection, credential requests/disclosure and unsafe admin requests.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_A = "['\u2019]"  # straight or curly apostrophe

_RULES: list[tuple[str, re.Pattern[str]]] = [
    # --- prompt injection
    ("prompt_injection", re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,20}\b(previous|prior|above|earlier|all|your|the)\b"
        r".{0,20}\b(instructions?|prompts?|rules|guidelines)\b", re.I)),
    ("prompt_injection", re.compile(r"\bsystem\s+prompt\b", re.I)),
    ("prompt_injection", re.compile(r"\b(developer|god|dan)\s+mode\b|\bjailbreak", re.I)),
    ("prompt_injection", re.compile(
        r"\byou\s+are\s+now\b|\bpretend\s+(to\s+be|you\s+are)\b|\breveal\s+(your|the)\s+(instructions|prompt|rules)\b",
        re.I)),
    # --- credential requests / disclosure
    ("credential_request", re.compile(
        rf"\b(admin|administrator|root|domain\s+admin|service[\s-]account)({_A}s)?\s+(password|credentials?|pwd)\b",
        re.I)),
    ("credential_request", re.compile(
        rf"\b(give|send|tell|show|share)\s+me\s+(the\s+|a\s+|your\s+|his\s+|her\s+|their\s+|someone{_A}?s\s+)?"
        r"(secret|password|credentials?|api\s*key|token|passcode)s?\b(?!\s*reset)", re.I)),
    ("credential_request", re.compile(rf"\bwhat\s+is\s+(the|his|her|their|\w+{_A}s)\s+password\b", re.I)),
    # --- unsafe admin requests
    ("unsafe_admin", re.compile(
        r"\b(disable|turn\s+off|remove|bypass|deactivate|skip)\s+(my\s+|the\s+|his\s+|her\s+|their\s+)?"
        r"(mfa|2fa|multi[\s-]?factor|two[\s-]?factor)\b", re.I)),
    ("unsafe_admin", re.compile(
        r"\bmake\s+me\s+(an?\s+)?(local\s+|global\s+|domain\s+)?(admin|administrator|root|superuser)\b", re.I)),
    ("unsafe_admin", re.compile(
        r"\b(give|grant)\s+me\s+(local\s+|global\s+|domain\s+)?(admin|administrator|root|elevated|full)\s+"
        r"(rights|access|privileges?|permissions)\b", re.I)),
    ("unsafe_admin", re.compile(r"\badd\s+me\s+to\s+(the\s+)?(domain\s+admins|administrators|admin\s+group)\b", re.I)),
    ("unsafe_admin", re.compile(
        rf"\breset\s+(someone\s+else{_A}?s|another\s+user{_A}?s|other\s+users{_A}?|his|her|their|"
        rf"my\s+(boss|manager|colleague){_A}?s?|the\s+ceo{_A}?s|[a-z]+{_A}s)\s+password", re.I)),
]


@dataclass
class GuardrailResult:
    blocked: bool
    category: str | None = None  # prompt_injection | credential_request | unsafe_admin
    matched: list[str] = field(default_factory=list)

    @property
    def injection(self) -> bool:
        return self.category == "prompt_injection"


def check_input(message: str) -> GuardrailResult:
    text = message or ""
    for category, pattern in _RULES:
        m = pattern.search(text)
        if m:
            return GuardrailResult(True, category, [m.group(0)])
    return GuardrailResult(False)
