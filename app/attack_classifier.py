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
from functools import lru_cache

from transformers import pipeline


THRESHOLD = int(os.getenv("ATTACK_SIZE_THRESHOLD", "1000"))


@lru_cache()
def _get_classifier():
    """Return a zero-shot classification pipeline.

    The model can be customised via the ``ATTACK_CLASSIFY_MODEL`` environment
    variable.  ``facebook/bart-large-mnli`` is used by default.
    """

    model_name = os.getenv("ATTACK_CLASSIFY_MODEL", "facebook/bart-large-mnli")
    return pipeline("zero-shot-classification", model=model_name)


_CANDIDATES = ["dos", "xss", "sqli", "cmd_injection", "path_traversal", "normal"]


def ml_multiclass_predict(text: str) -> str:
    """Classify ``text`` using a language model."""

    clf = _get_classifier()
    try:
        result = clf(text, candidate_labels=_CANDIDATES, multi_label=False)
        if result and "labels" in result:
            return str(result["labels"][0])
    except Exception:
        pass
    return "normal"


_XSS_PAT = re.compile(r"<script|javascript:|onerror=", re.IGNORECASE)
_SQLI_PAT = re.compile(r"('|%27).*(or|and).*(=|like)|union(.*?)select", re.IGNORECASE)
_TRAVERSAL_PAT = re.compile(r"\.\./")
_CMD_PAT = re.compile(r"(;|&&|\|)\s*(cat|ls|whoami|id)")


def classify(text: str) -> str:
    """Return a coarse attack category for ``text``.

    ``text`` may contain URL-encoded characters so we first decode it. The
    classification order is:

    1. Large payloads are labelled ``dos`` because they are often associated
       with denial of service attempts.
    2. Pattern based checks for common attack vectors such as XSS or SQLi.
    3. Fallback to ``ml_multiclass_predict`` which may use a real model if
       configured, otherwise ``normal``.
    """

    from urllib.parse import unquote_plus

    decoded = unquote_plus(text)

    if len(decoded) > THRESHOLD:
        return "dos"
    if _XSS_PAT.search(decoded):
        return "xss"
    if _SQLI_PAT.search(decoded):
        return "sqli"
    if _TRAVERSAL_PAT.search(decoded):
        return "path_traversal"
    if _CMD_PAT.search(decoded):
        return "cmd_injection"
    return ml_multiclass_predict(decoded)
