import re
import subprocess

from . import db


def is_ip_blocked(ip: str) -> bool:
    """Check if the IP already appears in UFW rules."""
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            capture_output=True,
            text=True,
            check=True,
        )
        return ip in result.stdout
    except Exception:
        return False


def block_ip(ip: str) -> bool:
    """Block the given IP using UFW. Returns True if command succeeds."""
    if is_ip_blocked(ip):
        return False
    try:
        subprocess.run(
            ["sudo", "ufw", "insert", "1", "deny", "from", ip],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return True
    except Exception as exc:
        print(f"Erro ao bloquear IP {ip}: {exc}")
        return False


def get_ufw_blocked_ips() -> set:
    """Return the current set of blocked IPs from UFW rules."""
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status", "numbered"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception as exc:
        print(f"Erro ao obter IPs do UFW: {exc}")
        return set()

    ips = set()
    for line in result.stdout.splitlines():
        if "DENY" in line:
            match = re.search(r"from\s+(\S+)", line)
            if match:
                ips.add(match.group(1))
            else:
                parts = line.split()
                for part in parts:
                    if re.match(r"\d+\.\d+\.\d+\.\d+", part):
                        ips.add(part)
                        break
    return ips


def sync_blocked_ips_with_ufw() -> set:
    """Synchronize blocked IPs in the database with current UFW rules."""
    ufw_ips = get_ufw_blocked_ips()
    if db.conn is None:
        return ufw_ips

    with db.conn.cursor() as cur:
        cur.execute("SELECT ip FROM blocked_ips WHERE status = 'blocked'")
        current_blocked = {row[0] for row in cur.fetchall()}

    # insert new blocked IPs
    for ip in ufw_ips - current_blocked:
        db.save_blocked_ip(ip, "ufw", "blocked")

    # mark IPs no longer blocked
    for ip in current_blocked - ufw_ips:
        with db.conn.cursor() as cur:
            cur.execute(
                "UPDATE blocked_ips SET status='unblocked' WHERE ip=%s AND status='blocked'",
                (ip,),
            )

    return ufw_ips
