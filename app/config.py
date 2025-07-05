import os
import re
from dotenv import load_dotenv

load_dotenv()


def sanitize_ifname(iface: str) -> str:
    """Return a clean interface name without NUL bytes or stray characters."""
    if not isinstance(iface, str):
        iface = str(iface)

    # split at first NUL in case the string contains embedded characters
    iface = iface.split("\x00", 1)[0]

    # remove newlines and control characters
    iface = re.sub(r"[\r\n\t\f\v]", "", iface)

    # keep only common iface characters (alnum, dash, underscore, colon, dot)
    iface = re.sub(r"[^A-Za-z0-9_:\-\.]+", "", iface)

    return iface.strip()

POSTGRES_USER = os.getenv('POSTGRES_USER')
POSTGRES_PASSWORD = os.getenv('POSTGRES_PASSWORD')
POSTGRES_DB = os.getenv('POSTGRES_DB')
POSTGRES_HOST = os.getenv('POSTGRES_HOST')
POSTGRES_PORT = int(os.getenv('POSTGRES_PORT', 5432))

SEMANTIC_MODEL = os.getenv('SEMANTIC_MODEL')
SEVERITY_MODEL = os.getenv('SEVERITY_MODEL')
ANOMALY_MODEL = os.getenv('ANOMALY_MODEL')
NIDS_MODEL = os.getenv('NIDS_MODEL')

NETWORK_INTERFACE = sanitize_ifname(os.getenv('NETWORK_INTERFACE', 'eth0'))
DEVICE = os.getenv('DEVICE', 'cpu')
WEB_PANEL_PORT = int(os.getenv('WEB_PANEL_PORT', '8080'))
