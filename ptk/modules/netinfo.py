"""Local network / environment information (no target, no root)."""

import socket

from ..core import colors, http


def run(logger=None):
    """Report local hostname, local IP, and public IP (best effort)."""
    print(colors.info("Local network information"))
    info = {}

    hostname = socket.gethostname()
    info["hostname"] = hostname
    print(colors.ok(f"Hostname: {hostname}"))

    # Local outbound IP (no traffic actually sent by connect on UDP socket).
    local_ip = "unknown"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    info["local_ip"] = local_ip
    print(colors.ok(f"Local IP: {local_ip}"))

    # Public IP via a plain HTTPS endpoint.
    public_ip = "unknown"
    try:
        resp = http.fetch("https://api.ipify.org", timeout=6.0)
        public_ip = http.read_body(resp, 64).strip()
    except (OSError, ValueError):
        pass
    info["public_ip"] = public_ip
    print(colors.ok(f"Public IP: {public_ip}"))

    if logger:
        logger.event("netinfo", local_ip, f"public={public_ip}")
    return info
