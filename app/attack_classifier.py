"""Simple rule-based attack classifier.

This module previously returned ``dos`` for any log larger than a threshold and
``normal`` for everything else. That behaviour caused the web interface to
display ``DDoS`` for nearly every log entry because the fallback network IDS
model (``Sniffer.AI``) also returned ``DDoS`` for most HTTP requests.  To make
the output more useful we implement a few lightweight heuristics that detect
common web attacks.  The goal is not to be perfect but to provide sensible
labels for the demo environment when specialised models are unavailable.
"""

from __future__ import annotations

import os
import re


THRESHOLD = int(os.getenv("ATTACK_SIZE_THRESHOLD", "1000"))


def ml_multiclass_predict(text: str) -> str:
    """Placeholder for a real ML classifier.

    When a custom model is configured this function can be replaced with an
    actual prediction call.  Until then it returns ``normal`` so that rule based
    checks below handle most cases.
    """

    return "normal"


_XSS_PAT = re.compile(r"<script|javascript:|onerror=", re.IGNORECASE)
_SQLI_PAT = re.compile(r"('|%27).*(or|and).*(=|like)|union(.*?)select", re.IGNORECASE)
_TRAVERSAL_PAT = re.compile(r"\.\./")
_CMD_PAT = re.compile(r"(;|&&|\|)\s*(cat|ls|whoami|id)")


def classify(text: str) -> str:
    """Return a coarse attack category for ``text``.

    The classification order is:

    1. Large payloads are labelled ``dos`` because they are often associated
       with denial of service attempts.
    2. Pattern based checks for common attack vectors such as XSS or SQLi.
    3. Fallback to ``ml_multiclass_predict`` which may use a real model if
       configured, otherwise ``normal``.
    """

    if len(text) > THRESHOLD:
        return "dos"
    if _XSS_PAT.search(text):
        return "xss"
    if _SQLI_PAT.search(text):
        return "sqli"
    if _TRAVERSAL_PAT.search(text):
        return "path_traversal"
    if _CMD_PAT.search(text):
        return "cmd_injection"
    return ml_multiclass_predict(text)
