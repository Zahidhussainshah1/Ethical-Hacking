"""Reverse DNS lookups across a single host or a CIDR range."""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors


def _expand(target: str):
    net = ipaddress.ip_network(target.strip(), strict=False)
    if net.num_addresses > 65536:
        raise ValueError("range too large (max /16)")
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]


def _ptr(ip: str):
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return ip, name
    except (socket.herror, socket.gaierror, socket.error):
        return None


def run(target: str, workers: int = 50, logger=None):
    """Resolve PTR records for ``target`` (host or CIDR). Returns list of (ip, name)."""
    try:
        ips = _expand(target)
    except ValueError as e:
        print(colors.err(str(e)))
        return []

    print(colors.info(f"Reverse DNS for {colors.bold(target)} — {len(ips)} address(es)"))
    if logger:
        logger.event("reverse_dns", target, f"count={len(ips)}")

    found = []
    workers = max(1, min(workers, len(ips)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_ptr, ip) for ip in ips]
        try:
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    found.append(res)
                    print(colors.ok(f"{res[0]:<16} -> {res[1]}"))
        except KeyboardInterrupt:
            print(colors.warn("\nInterrupted."))

    found.sort()
    print(colors.info(f"{len(found)} PTR record(s) found."))
    if logger:
        logger.event("reverse_dns", target, f"found={len(found)}")
    return found
