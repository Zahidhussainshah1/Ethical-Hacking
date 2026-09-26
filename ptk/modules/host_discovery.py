"""TCP-based host discovery (ping sweep without root/ICMP).

ICMP ping needs raw sockets (root), which Termux users usually don't have.
Instead we probe a few common TCP ports per host: a host is considered "up" if
any probe connects OR is actively refused (RST) — both prove the host is
reachable. Connection timeouts are treated as down/filtered.
"""

import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors

_PROBE_PORTS = [80, 443, 22, 445, 3389]


def _expand(target: str):
    """Expand a CIDR (10.0.0.0/24) or single host into a list of IP strings."""
    target = target.strip()
    try:
        net = ipaddress.ip_network(target, strict=False)
        # Guard against absurdly large sweeps.
        if net.num_addresses > 65536:
            raise ValueError("range too large (max /16)")
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        # Not a network — try as a single hostname/IP.
        return [target]


def _is_up(host: str, timeout: float):
    for port in _PROBE_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            rc = sock.connect_ex((host, port))
            if rc == 0 or rc == errno.ECONNREFUSED:
                return True
        except socket.error:
            pass
        finally:
            sock.close()
    return False


def run(target: str, timeout: float = 0.5, workers: int = 100, logger=None):
    """Sweep ``target`` (CIDR or host) for live hosts. Returns list of IPs."""
    try:
        hosts = _expand(target)
    except ValueError as e:
        print(colors.err(str(e)))
        return []

    print(colors.info(f"Host discovery across {colors.bold(target)} — "
                      f"{len(hosts)} address(es)"))
    if logger:
        logger.event("host_discovery", target, f"hosts={len(hosts)}")

    alive = []
    workers = max(1, min(workers, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_is_up, h, timeout): h for h in hosts}
        try:
            for fut in as_completed(futures):
                host = futures[fut]
                if fut.result():
                    alive.append(host)
                    print(colors.ok(f"{host} is up"))
        except KeyboardInterrupt:
            print(colors.warn("\nSweep interrupted."))

    alive.sort(key=lambda h: tuple(int(x) for x in h.split(".")) if h.count(".") == 3 else h)
    print(colors.info(f"{len(alive)} host(s) up."))
    if logger:
        logger.event("host_discovery", target, f"up={len(alive)}")
    return alive
