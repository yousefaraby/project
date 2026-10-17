"""Step 0b: security keyword scan (English + Arabic). Independent safety net from triage."""
from __future__ import annotations

import re

_EN: list[tuple[str, re.Pattern[str]]] = [
    ("phishing", re.compile(r"\bphish(ing|ed|y)?\b", re.I)),
    ("ransomware", re.compile(r"\bransom(ware)?\b", re.I)),
    ("hacked", re.compile(r"\bhack(ed|er|ers|ing)?\b", re.I)),
    ("password_leaked", re.compile(
        r"\bpassword\w*\s+(was\s+|got\s+|has\s+been\s+|have\s+been\s+|is\s+)?(leaked|stolen|exposed|compromised)\b"
        r"|\b(leaked|stolen|exposed)\s+(my\s+)?passwords?\b", re.I)),
    ("malware", re.compile(r"\b(malware|virus|trojan|spyware|keylogger)\b", re.I)),
    ("compromised", re.compile(r"\bcompromi[sz]ed\b|\bdata\s+breach\b", re.I)),
]

# Arabic: no \b (prefixes like ال / و / ب attach to words) - match normalized stems.
_AR: list[tuple[str, re.Pattern[str]]] = [
    ("phishing", re.compile(r"تصيد|احتيال")),
    ("ransomware", re.compile(r"فدية|فديه")),
    ("hacked", re.compile(r"اختراق|اخترق|مخترق|هكر|تهكير")),
    ("password_leaked", re.compile(
        r"(تسريب|تسرب|سرقة|سرقه)\s*(كلمة|كلمه|كلمات)\s*(ال)?(مرور|سر)"
        r"|(كلمة|كلمه)\s*(ال)?(مرور|سر).{0,15}(مسرب|تسرب|مسروق|سرقت)")),
    ("malware", re.compile(r"خبيث|فيروس|فايروس|تروجان")),
    ("compromised", re.compile(r"مخترق|مكشوف|تم\s*اختراق")),
]

_DIACRITICS = re.compile(r"[\u064B-\u065F\u0670\u0640]")  # harakat + tatweel


def _normalize_ar(text: str) -> str:
    text = _DIACRITICS.sub("", text)
    return text.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا")


def scan_keywords(message: str) -> list[str]:
    """Returns the sorted, de-duplicated list of security labels found."""
    text = message or ""
    norm = _normalize_ar(text)
    hits = {label for label, p in _EN if p.search(text)}
    hits |= {label for label, p in _AR if p.search(norm)}
    return sorted(hits)
