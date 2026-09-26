"""Service banner grabber.

Connects to a TCP port and reads whatever the service announces. Useful for
identifying service versions during authorized recon.
"""

import socket

from ..core import colors, utils

# Probes that coax a banner out of common text protocols.
_PROBES = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
}


def _grab(ip: str, port: int, timeout: float):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        probe = _PROBES.get(port)
        if probe:
            sock.sendall(probe)
        data = sock.recv(4096)
        return data.decode("utf-8", errors="replace").strip()
    except socket.error:
        return None
    finally:
        sock.close()


def run(target: str, port: int, timeout: float = 5.0, logger=None):
    """Grab a banner from ``target`` on ``port``. Returns the banner string or None."""
    host = utils.normalize_host(target)
    ip = utils.resolve(host)
    if ip is None:
        print(colors.err(f"Could not resolve host: {host}"))
        return None

    print(colors.info(f"Grabbing banner from {colors.bold(host)}:{port} ({ip})"))
    if logger:
        logger.event("banner_grab", host, f"port={port}")

    banner = _grab(ip, port, timeout)
    if not banner:
        print(colors.warn("No banner received."))
        return None

    print(colors.dim("-" * 40))
    for line in banner.splitlines():
        print(colors.green(f"  {line}"))
    print(colors.dim("-" * 40))
    if logger:
        logger.event("banner_grab", host, f"port={port} bytes={len(banner)}")
    return banner
