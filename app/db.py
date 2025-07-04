import psycopg2
from psycopg2.extras import RealDictCursor
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

def init_db():
    if conn is None:
        return
    with conn.cursor() as cur:
        with open('/app/schema.sql') as f:
            cur.execute(f.read())


def save_log(interface, data, severity, anomaly):
    if conn is None:
        return
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO logs (iface, log, severity, anomaly) VALUES (%s, %s, %s, %s)
            """,
            (interface, data, severity, anomaly),
        )
