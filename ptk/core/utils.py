"""Shared helpers: target parsing and validation."""

import ipaddress
import re
import socket
from urllib.parse import urlparse

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def normalize_host(target: str) -> str:
    """Strip scheme/path from a URL-ish target, returning just the host."""
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    # Handle host:port
    if target.count(":") == 1 and not _is_ipv6(target):
        return target.split(":", 1)[0]
    return target


def _is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_valid_host(target: str) -> bool:
    """True if target is a valid IP address or hostname."""
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(target))


def resolve(host: str):
    """Resolve a hostname to an IP, or return None on failure."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, socket.error):
        return None


def parse_ports(spec: str):
    """Parse a port spec like '22,80,443' or '1-1024' into a sorted list.

    Raises ValueError on invalid input or out-of-range ports.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, hi + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
    if not ports:
        raise ValueError("no ports specified")
    return sorted(ports)
