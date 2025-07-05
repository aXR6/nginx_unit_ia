import os
import re


THRESHOLD = int(os.getenv("ATTACK_SIZE_THRESHOLD", "1000"))


def ml_multiclass_predict(text: str) -> str:
    """Placeholder ML classification returning ``normal`` by default."""
    return "normal"


def _load_patterns():
    # Regex based on OWASP/BlackHat patterns. See examcollection.com/blog/regex-explained
    # and https://pt.wikipedia.org/wiki/ReDoS for background.
    return [
        # XSS – javascript in tags or attributes
        (
            re.compile(
                r"<\s*(script|img|iframe)[^>]*(src|onerror|onload)\s*=\s*['\"]?javascript:",
                re.I,
            ),
            "xss",
        ),
        # SQLi – single quotes, comments and dangerous keywords
        (
            re.compile(
                r"(\%27)|(')|(--)|(\%23)|(#)|\b(select|insert|update|delete|union|drop)\b",
                re.I,
            ),
            "sql_injection",
        ),
        # Path Traversal – ../ or encoded variants
        (re.compile(r"(\.\./|\.\.\\|%2e%2e/)", re.I), "path_traversal"),
        # Command Injection – shell metacharacters
        (re.compile(r"[;&|`]|/(bin/)?(bash|sh|cat)\b", re.I), "command_injection"),
        # LFI/RFI – include file protocols
        (
            re.compile(r"\b(include|require|php://|ftp://|file://)\b", re.I),
            "file_inclusion",
        ),
        # Open Redirect – raw URL parameter
        (re.compile(r"(https?:\\/\\/)[^ ]+", re.I), "open_redirect"),
        # XXE – external entity declaration
        (re.compile(r"<!DOCTYPE\s+[^>]*ENTITY\s+SYSTEM", re.I), "xxe"),
        # Header Injection – CRLF characters
        (re.compile(r"%0d|%0a|\r|\n", re.I), "header_injection"),
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
