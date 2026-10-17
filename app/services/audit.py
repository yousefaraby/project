"""SQLite audit log + secret redaction."""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.config import audit_db_path

REDACTED = "[REDACTED]"

# Order matters: specific patterns first, generic ones last.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Bearer tokens
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), f"Bearer {REDACTED}"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), REDACTED),
    # Vendor-style API keys (sk-..., ghp_..., xoxb-...)
    (re.compile(r"\b(?:sk|pk|ghp|gho|xox[abpr])[-_][A-Za-z0-9_-]{8,}"), REDACTED),
    # key/token/secret = value
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?key|token|secret|client[_-]?secret)\b(\s*(?:[:=]|is)\s*)(\S+)"),
     rf"\1\2{REDACTED}"),
    # password / pin = value  ("my password is hunter2", "pwd: x")
    (re.compile(r"(?i)\b(password|passwd|pwd|passcode|pin)\b(\s*(?:[:=]|is|was)\s*)(\S+)"),
     rf"\1\2{REDACTED}"),
    # verification / MFA / OTP codes followed by digits
    (re.compile(r"(?i)\b((?:verification|mfa|2fa|otp|one[- ]time|security|sms)?\s*code|otp)\b(\s*(?:[:=]|is|was)?\s*)(\d[\d -]{2,10}\d)"),
     rf"\1\2{REDACTED}"),
    # Standalone 6-8 digit numbers (likely OTPs)
    (re.compile(r"\b\d{6,8}\b"), REDACTED),
    # Long opaque strings (32+ chars of token alphabet)
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), REDACTED),
]


def redact(text: str | None) -> str:
    if not text:
        return text or ""
    out = text
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditRecord(BaseModel):
    incident_id: str | None = None
    timestamp: str = Field(default_factory=_now)
    user_id: str
    redacted_message: str = ""
    triage: dict[str, Any] = Field(default_factory=dict)
    kw_flag: bool = False
    escalation_reasons: list[str] = Field(default_factory=list)
    plan: dict[str, Any] = Field(default_factory=dict)
    tool_results: list[dict[str, Any]] = Field(default_factory=list)
    tool_errors: list[dict[str, Any]] = Field(default_factory=list)
    eval_attempts: int = 0
    eval_verdicts: list[dict[str, Any]] = Field(default_factory=list)
    outcome: str
    reply_sent: bool = False
    duration_ms: float = 0.0


_JSON_FIELDS = ("triage", "escalation_reasons", "plan", "tool_results", "tool_errors", "eval_verdicts")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    timestamp TEXT NOT NULL,
    user_id TEXT NOT NULL,
    redacted_message TEXT,
    triage TEXT,
    kw_flag INTEGER,
    escalation_reasons TEXT,
    plan TEXT,
    tool_results TEXT,
    tool_errors TEXT,
    eval_attempts INTEGER,
    eval_verdicts TEXT,
    outcome TEXT NOT NULL,
    reply_sent INTEGER,
    duration_ms REAL
)
"""

_COLUMNS = list(AuditRecord.model_fields)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(audit_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA)
    return conn


def write_audit(record: AuditRecord) -> int:
    row = record.model_dump()
    row["redacted_message"] = redact(row["redacted_message"])  # defense in depth
    for f in _JSON_FIELDS:
        row[f] = json.dumps(row[f], ensure_ascii=False, default=str)
    row["kw_flag"] = int(row["kw_flag"])
    row["reply_sent"] = int(row["reply_sent"])
    sql = f"INSERT INTO audit ({', '.join(_COLUMNS)}) VALUES ({', '.join('?' for _ in _COLUMNS)})"
    with closing(_connect()) as conn, conn:
        cur = conn.execute(sql, [row[c] for c in _COLUMNS])
        return int(cur.lastrowid)


def _decode(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    for f in _JSON_FIELDS:
        d[f] = json.loads(d[f]) if d[f] else None
    d["kw_flag"] = bool(d["kw_flag"])
    d["reply_sent"] = bool(d["reply_sent"])
    return d


def get_audit_records(incident_id: str) -> list[dict[str, Any]]:
    with closing(_connect()) as conn:
        rows = conn.execute("SELECT * FROM audit WHERE incident_id = ? ORDER BY id", (incident_id,)).fetchall()
    return [_decode(r) for r in rows]


def get_audit_record_by_id(record_id: int) -> dict[str, Any] | None:
    with closing(_connect()) as conn:
        row = conn.execute("SELECT * FROM audit WHERE id = ?", (record_id,)).fetchone()
    return _decode(row) if row else None


def list_audit_records(limit: int = 100) -> list[dict[str, Any]]:
    with closing(_connect()) as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_decode(r) for r in rows]


def clear_audit() -> None:
    with closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM audit")
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'audit'")
