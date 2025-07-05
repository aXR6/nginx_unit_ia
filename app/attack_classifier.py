import re

PATTERNS = [
    (re.compile(r"<script", re.I), "xss"),
    (re.compile(r"(\bselect\b|\binsert\b|\bunion\b|\bdrop\b|\bor\s+1=1)", re.I), "sql_injection"),
    (re.compile(r"\.\./|\.\.\\"), "path_traversal"),
    (re.compile(r"[;&|`]|\b(cat|bash|sh)\b", re.I), "command_injection"),
]


def classify(text: str) -> str:
    """Return a simple attack type label based on regex patterns."""
    for pattern, label in PATTERNS:
        if pattern.search(text):
            return label
    if len(text) > 1000:
        return "dos"
    return "normal"
