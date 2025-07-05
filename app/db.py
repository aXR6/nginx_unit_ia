import os
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor, Json
from . import config

conn = None
if config.POSTGRES_HOST:
    conn = psycopg2.connect(
        dbname=config.POSTGRES_DB,
        user=config.POSTGRES_USER,
        password=config.POSTGRES_PASSWORD,
        host=config.POSTGRES_HOST,
        port=config.POSTGRES_PORT,
    )
    conn.autocommit = True

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def init_db():
    if conn is None:
        return
    with conn.cursor() as cur:
        with open(SCHEMA_PATH) as f:
            cur.execute(f.read())


def save_log(interface, data, severity, anomaly, nids, semantic=None):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO logs (iface, log, severity, anomaly, nids, semantic)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                interface,
                data,
                Json(severity),
                Json(anomaly),
                Json(nids),
                Json(semantic) if semantic is not None else None,
            ),
        )


def save_blocked_ip(ip, reason, status="blocked"):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO blocked_ips (ip, reason, status)
            VALUES (%s, %s, %s)
            """,
            (ip, reason, status),
        )


def get_logs(limit=100, offset=0):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT * FROM logs
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        return cur.fetchall()


def get_blocked_ips(limit=100, offset=0):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT * FROM blocked_ips
            ORDER BY blocked_at DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        return cur.fetchall()


def add_whitelist_ip(ip: str):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO whitelist_ips (ip)
            VALUES (%s)
            ON CONFLICT (ip) DO NOTHING
            """,
            (ip,),
        )


def remove_whitelist_ip(ip: str):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("DELETE FROM whitelist_ips WHERE ip=%s", (ip,))


def get_whitelist_ips():
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT ip FROM whitelist_ips ORDER BY ip")
        return cur.fetchall()


def is_ip_whitelisted(ip: str) -> bool:
    if conn is None:
        return False
    with conn.cursor() as cur:
        cur.execute("SELECT 1 FROM whitelist_ips WHERE ip=%s", (ip,))
        return cur.fetchone() is not None
