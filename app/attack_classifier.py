import os
import re


THRESHOLD = int(os.getenv("ATTACK_SIZE_THRESHOLD", "1000"))


def ml_multiclass_predict(text: str) -> str:
    """Placeholder ML classification returning ``normal`` by default."""
    return "normal"


def _load_patterns():
    return [
        # XSS attempts including tag variations
        (
            re.compile(r"<\s*(script|img|iframe)[^>]*>.*?<\s*/\s*\1\s*>", re.I | re.S),
            "xss",
        ),
        # Common SQL injection keywords
        (
            re.compile(
                r"(?i)(?:union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1=1)"
            ),
            "sql_injection",
        ),
        # Directory traversal including encoded variants
        (re.compile(r"(?:\.\.\/|\.\.\\|%2e%2e\/|%2e%2e\\)", re.I), "path_traversal"),
        # Command injection characters
        (re.compile(r"[;&|`]|\b(cat|bash|sh)\b", re.I), "command_injection"),
        # URLs inside parameters that may indicate open redirect
        (re.compile(r"(?:https?|ftp)://[^\s\"']+", re.I), "open_redirect"),
        # File inclusion patterns
        (
            re.compile(r"(?:\binclude\b|\brequire\b)[^\n]+\.(?:php|cfg|txt)", re.I),
            "file_inclusion",
        ),
        # XML External Entity
        (re.compile(r"<!DOCTYPE\s+[^>]*\[\s*<!ENTITY\s+[^>]*>", re.I), "xxe"),
        # HTTP header injection
        (re.compile(r"\r?\n\s*[A-Za-z-]+:", re.I), "header_injection"),
        # Hidden field tampering
        (re.compile(r"hidden\s*=\s*['\"]?\w+['\"]?", re.I), "form_tampering"),
    ]


PATTERNS = _load_patterns()


def classify(text: str) -> str:
    """Classify the text into an attack category."""
    for pattern, label in PATTERNS:
        if pattern.search(text):
            return label
    if len(text) > THRESHOLD:
        return "dos"
    return ml_multiclass_predict(text)
