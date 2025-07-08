import logging
import json
import subprocess

logger = logging.getLogger(__name__)


def fetch_ip_info(ip: str):
    """Return IP information using the ipinfo CLI or None on failure."""
    try:
        result = subprocess.run(
            ["ipinfo", ip, "--json"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        logger.error("ipinfo CLI error for %s: %s", ip, result.stderr.strip())
    except Exception as exc:
        logger.error("Failed to fetch IP info for %s: %s", ip, exc)
    return None
