"""WHOIS lookup.

Prefers the system ``whois`` binary (Termux: pkg install whois). Falls back to
a direct TCP query against IANA's WHOIS referral server on port 43.
"""

import shutil
import socket
import subprocess

from ..core import colors, utils

_IANA_WHOIS = "whois.iana.org"


def _system_whois(host: str):
    binary = shutil.which("whois")
    if not binary:
        return None
    try:
        out = subprocess.run(
            [binary, host], capture_output=True, text=True, timeout=20
        )
        return out.stdout
    except (subprocess.SubprocessError, OSError):
        return None


def _socket_whois(host: str, server: str = _IANA_WHOIS):
    try:
        with socket.create_connection((server, 43), timeout=15) as sock:
            sock.sendall((host + "\r\n").encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    except socket.error as e:
        print(colors.err(f"WHOIS socket query failed: {e}"))
        return None


def run(target: str, logger=None):
    """Perform a WHOIS lookup for ``target``. Returns the raw response text."""
    host = utils.normalize_host(target)
    print(colors.info(f"WHOIS lookup for {colors.bold(host)}"))
    if logger:
        logger.event("whois", host)

    result = _system_whois(host)
    if result is None:
        print(colors.warn("'whois' binary not found — using socket fallback."))
        print(colors.dim("    For richer output: pkg install whois"))
        result = _socket_whois(host)

    if not result:
        print(colors.err("No WHOIS data returned."))
        return None

    # Show only informative lines, trimming blank noise.
    for line in result.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("%") and not stripped.startswith("#"):
            print(colors.green(f"  {stripped}"))
    if logger:
        logger.event("whois", host, "ok")
    return result
