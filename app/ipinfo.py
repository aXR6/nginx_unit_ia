import logging
import json
import os
import subprocess

logger = logging.getLogger(__name__)


def fetch_ip_info(ip: str):
    """Return IP information using the ipinfo CLI or None on failure."""
    try:
        cmd = ["docker", "run", "--rm"]
        config_dir = os.environ.get("IPINFO_CONFIG_DIR")
        if config_dir:
            cmd.extend(["-v", f"{config_dir}:/root/.config/ipinfo"])

        token = os.environ.get("IPINFO_TOKEN")
        mmdb_path = os.environ.get(
            "IPINFO_MMDB",
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "mmdb", "ipinfo_lite.mmdb"),
        )

        if os.path.exists(mmdb_path):
            cmd.extend(["-v", f"{mmdb_path}:/db.mmdb"])
            cmd.extend(["ipinfo/ipinfo:3.3.1", "mmdb", "read", ip, "/db.mmdb", "--format", "json"])
        else:
            cmd.append("ipinfo/ipinfo:3.3.1")
            if token:
                cmd.extend(["-t", token])
            cmd.extend([ip, "--json"])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        logger.error("ipinfo CLI error for %s: %s", ip, result.stderr.strip())
    except Exception as exc:
        logger.error("Failed to fetch IP info for %s: %s", ip, exc)
    return None
