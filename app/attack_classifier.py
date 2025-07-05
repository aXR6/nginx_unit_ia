import os
import re


THRESHOLD = int(os.getenv("ATTACK_SIZE_THRESHOLD", "1000"))


def ml_multiclass_predict(text: str) -> str:
    """Placeholder ML classification returning ``normal`` by default."""
    return "normal"


def _load_patterns():
    # Regex based on common attack patterns documented by OWASP and other
    # security references. Designed to avoid catastrophic backtracking.
    return [
        # SQL Injection
        (
            re.compile(
                r"(\%27)|(')|(--)|(\%23)|(#)|\b(select|insert|update|delete|union|drop|exec|declare)\b",
                re.I,
            ),
            "sql_injection",
        ),
        # XSS (tags with javascript expressions)
        (
            re.compile(
                r"<\s*(script|img|iframe|svg)[^>]*(src|onerror|onload|javascript|alert)\s*=",
                re.I,
            ),
            "xss",
        ),
        # SSRF – unexpected URLs in input
        (re.compile(r"\b(http|https|ftp):\/\/[^\s\"]+", re.I), "ssrf"),
        # XXE – external entity declaration
        (re.compile(r"<!DOCTYPE\s+[^>]*ENTITY\s+SYSTEM", re.I), "xxe"),
        # Path Traversal – ../ or encoded variants
        (re.compile(r"(\.\./|\.\.\\|%2e%2e/)", re.I), "path_traversal"),
        # Command Injection – shell metacharacters
        (re.compile(r"[;&|`]|/(bin/)?(bash|sh|cat)\b", re.I), "command_injection"),
        # File Inclusion
        (
            re.compile(r"\b(include|require|php://|file://|ftp://)\b", re.I),
            "file_inclusion",
        ),
        # Open Redirect
        (re.compile(r"(redirect|url|next)=https?:\/\/[^\s\"]+", re.I), "open_redirect"),
        # Header or CRLF Injection
        (re.compile(r"(\r\n|\r|\n|%0d|%0a)", re.I), "header_injection"),
        # Credential stuffing / brute force
        (re.compile(r"(?:(?:failed)\s+login|\bauthentication\s+failed\b)", re.I), "brute_force"),
        # Phishing keywords followed by a link
        (re.compile(r"\b(click\s+here|account|verify|update|login)\b.*(http|https):\/\/", re.I), "phishing"),
        # Botnet or malware command lines
        (re.compile(r"\brundll32\.exe\s+\\\S{10,70}\.\S{10,70},\w{16}\b", re.I), "malware_botnet"),
        # Ransomware/Trojan words in logs
        (re.compile(r"\b(encrypt(ed)?|crypt|ransom|payload|C&C|botnet)\b", re.I), "malware_ransomware"),
        # IoT or emerging attack patterns
        (re.compile(r"\b(Mirai|botnet|CVE-\d{4}-\d{4,7})\b", re.I), "emerging_iot_attack"),
        # Slowloris / DoS keywords
        (re.compile(r"\bSlowloris\b", re.I), "dos"),
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
