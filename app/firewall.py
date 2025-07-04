import subprocess


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
