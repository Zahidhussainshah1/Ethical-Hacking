"""DNS reconnaissance using the standard library resolver.

Looks up common record types via socket calls plus optional ``dig`` if it is
available on the system (common in Termux via the dnsutils package).
"""

import shutil
import socket
import subprocess

from ..core import colors, utils

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _basic_lookup(host: str):
    """Resolve A/AAAA records with the stdlib (no external deps)."""
    results = {"A": [], "AAAA": []}
    try:
        infos = socket.getaddrinfo(host, None)
        for family, _, _, _, sockaddr in infos:
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in results["A"]:
                results["A"].append(addr)
            elif family == socket.AF_INET6 and addr not in results["AAAA"]:
                results["AAAA"].append(addr)
    except socket.gaierror:
        pass
    return results


def _dig_lookup(host: str, rtype: str):
    dig = shutil.which("dig")
    if not dig:
        return []
    try:
        out = subprocess.run(
            [dig, "+short", host, rtype],
            capture_output=True, text=True, timeout=10,
        )
        return [line for line in out.stdout.splitlines() if line.strip()]
    except (subprocess.SubprocessError, OSError):
        return []


def run(target: str, logger=None):
    """Perform DNS recon against ``target``. Returns a dict of record type -> list."""
    host = utils.normalize_host(target)
    print(colors.info(f"DNS recon for {colors.bold(host)}"))
    if logger:
        logger.event("dns_recon", host)

    records = {}
    have_dig = shutil.which("dig") is not None

    if have_dig:
        for rtype in _RECORD_TYPES:
            values = _dig_lookup(host, rtype)
            if values:
                records[rtype] = values
    else:
        print(colors.warn("'dig' not found — falling back to A/AAAA lookup only."))
        print(colors.dim("    Install with: pkg install dnsutils"))
        basic = _basic_lookup(host)
        records = {k: v for k, v in basic.items() if v}

    if not records:
        print(colors.warn("No DNS records found."))
    for rtype, values in records.items():
        for value in values:
            print(colors.ok(f"{rtype:<6} {value}"))

    if logger:
        logger.event("dns_recon", host, f"types={list(records.keys())}")
    return records
