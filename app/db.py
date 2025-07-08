import os
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor, Json
from . import config


def _is_attack_label(label: str) -> bool:
    """Return True if label represents an attack."""
    return str(label).lower() not in ("normal", "benign", "none")


def _is_attack_entry(nids: dict) -> bool:
    label = nids.get("majority", nids.get("label"))
    return _is_attack_label(label)


conn = None
if config.POSTGRES_HOST:
    try:
        conn = psycopg2.connect(
            dbname=config.POSTGRES_DB,
            user=config.POSTGRES_USER,
            password=config.POSTGRES_PASSWORD,
            host=config.POSTGRES_HOST,
            port=config.POSTGRES_PORT,
        )
    except Exception:
        conn = None
    if conn is not None:
        conn.autocommit = True

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def init_db():
    if conn is None:
        return
    with conn.cursor() as cur:
        with open(SCHEMA_PATH) as f:
            cur.execute(f.read())


def save_log(
    interface, data, severity, anomaly, nids, semantic=None, ip=None, ip_info=None
):
    """Persist the log in the appropriate table based on attack classification."""
    if conn is None:
        return None

    table = "threat_logs" if _is_attack_entry(nids) else "common_logs"
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            f"""
            INSERT INTO {table} (iface, log, ip, ip_info, severity, anomaly, nids, semantic)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, created_at
            """,
            (
                interface,
                data,
                ip,
                Json(ip_info) if ip_info is not None else None,
                Json(severity),
                Json(anomaly),
                Json(nids),
                Json(semantic) if semantic is not None else None,
            ),
        )
        row = cur.fetchone()
        return row["id"], row["created_at"]


def save_blocked_ip(ip, reason, status="blocked", ip_info=None):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO blocked_ips (ip, reason, ip_info, status)
            VALUES (%s, %s, %s, %s)
            """,
            (ip, reason, Json(ip_info) if ip_info is not None else None, status),
        )


def get_logs(limit=100, offset=0):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT *, true AS is_attack FROM threat_logs
            UNION ALL
            SELECT *, false AS is_attack FROM common_logs
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        return cur.fetchall()


def get_threat_logs(limit=100, offset=0):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM threat_logs ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        for r in rows:
            r["is_attack"] = True
        return rows


def get_common_logs(limit=100, offset=0):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM common_logs ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        for r in rows:
            r["is_attack"] = False
        return rows


def get_log(log_id: int):
    if conn is None:
        return None
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT * FROM threat_logs WHERE id=%s", (log_id,))
        row = cur.fetchone()
        if row:
            row["is_attack"] = True
            return row
        cur.execute("SELECT * FROM common_logs WHERE id=%s", (log_id,))
        row = cur.fetchone()
        if row:
            row["is_attack"] = False
        return row


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


def get_blocked_ip(ip: str):
    if conn is None:
        return None
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM blocked_ips WHERE ip=%s ORDER BY blocked_at DESC LIMIT 1",
            (ip,),
        )
        return cur.fetchone()


def get_logs_by_ip(ip: str, limit: int = 20):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, created_at, log, true AS is_attack
            FROM threat_logs WHERE ip=%s
            UNION ALL
            SELECT id, created_at, log, false AS is_attack
            FROM common_logs WHERE ip=%s
            ORDER BY created_at DESC LIMIT %s
            """,
            (ip, ip, limit),
        )
        return cur.fetchall()


def unblock_ip(ip: str):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "UPDATE blocked_ips SET status='unblocked' WHERE ip=%s AND status='blocked'",
            (ip,),
        )


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
