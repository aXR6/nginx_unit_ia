from __future__ import annotations
import os
from typing import Optional

from opensearchpy import OpenSearch
from . import config

client: Optional[OpenSearch] = None

if config.ES_HOST:
    es_kwargs = {"hosts": [config.ES_HOST]}
    if config.ES_USER and config.ES_PASSWORD:
        es_kwargs["basic_auth"] = (config.ES_USER, config.ES_PASSWORD)
    client = OpenSearch(**es_kwargs)


def index_log(doc: dict) -> None:
    """Index a log document into OpenSearch."""
    if client is None:
        return
    try:
        client.index(index="logs", body=doc)
    except Exception as exc:
        # ignore indexing errors but log them for debugging
        import logging

        logging.getLogger(__name__).error("Failed to index log: %s", exc)


def index_blocked_ip(doc: dict) -> None:
    """Index blocked IP info into OpenSearch."""
    if client is None:
        return
    try:
        client.index(index="blocked_ips", body=doc)
    except Exception as exc:
        import logging

        logging.getLogger(__name__).error("Failed to index blocked ip: %s", exc)
