import logging
import requests

logger = logging.getLogger(__name__)


def fetch_ip_info(ip: str):
    """Return IP information from ipinfo.io or None on failure."""
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.ok:
            return resp.json()
    except Exception as exc:
        logger.error("Failed to fetch IP info for %s: %s", ip, exc)
    return None
