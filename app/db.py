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


def save_log(interface, data, severity, anomaly, nids):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO logs (iface, log, severity, anomaly, nids)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (interface, data, Json(severity), Json(anomaly), Json(nids)),
        )


def get_logs(limit=100):
    if conn is None:
        return []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            SELECT * FROM logs
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )
        return cur.fetchall()
