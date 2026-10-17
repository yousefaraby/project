"""Filesystem paths. Resolved lazily so tests can redirect via IR_DATA_DIR."""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def data_dir() -> Path:
    d = Path(os.environ.get("IR_DATA_DIR", str(PROJECT_ROOT / "data")))
    d.mkdir(parents=True, exist_ok=True)
    return d


def outbox_path() -> Path:
    return data_dir() / "outbox.jsonl"


def alerts_path() -> Path:
    return data_dir() / "alerts.jsonl"


def audit_db_path() -> Path:
    return data_dir() / "audit.db"
