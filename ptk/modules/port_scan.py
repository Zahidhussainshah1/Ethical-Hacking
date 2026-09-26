"""TCP connect port scanner.

Uses a thread pool of full TCP connect() attempts (no raw sockets, so it works
unprivileged inside Termux). Intended for authorized scanning of hosts within
an agreed scope.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors, utils

# A small, common-service default so a quick scan is meaningful without
# hammering all 65k ports.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443,
]

_SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 8080: "http-alt",
    8443: "https-alt",
}


def _service(port: int) -> str:
    if port in _SERVICE_NAMES:
        return _SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def _check_port(ip: str, port: int, timeout: float):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return port
    except socket.error:
        return None
    finally:
        sock.close()
    return None


def run(target: str, ports=None, timeout: float = 1.0, workers: int = 100, logger=None):
    """Scan ``target`` for open TCP ports.

    Returns a sorted list of (port, service) tuples for open ports.
    """
    host = utils.normalize_host(target)
    ip = utils.resolve(host)
    if ip is None:
        print(colors.err(f"Could not resolve host: {host}"))
        return []

    if ports is None:
        ports = COMMON_PORTS

    print(colors.info(f"Scanning {colors.bold(host)} ({ip}) — {len(ports)} ports, "
                      f"timeout {timeout}s"))
    if logger:
        logger.event("port_scan", host, f"ip={ip} ports={len(ports)}")

    open_ports = []
    workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_port, ip, p, timeout): p for p in ports}
        try:
            for fut in as_completed(futures):
                port = fut.result()
                if port is not None:
                    svc = _service(port)
                    open_ports.append((port, svc))
                    print(colors.ok(f"{port:>5}/tcp open  {svc}"))
        except KeyboardInterrupt:
            print(colors.warn("\nScan interrupted by user."))
            for f in futures:
                f.cancel()

    open_ports.sort()
    if not open_ports:
        print(colors.warn("No open ports found in the scanned range."))
    else:
        print(colors.info(f"{len(open_ports)} open port(s) found."))
    if logger:
        logger.event("port_scan", host, f"open={[p for p, _ in open_ports]}")
    return open_ports
