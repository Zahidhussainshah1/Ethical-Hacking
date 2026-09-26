"""Passive-style subdomain enumeration via DNS resolution of a wordlist.

Each candidate ``sub.domain`` is resolved with the stdlib. This only queries
public DNS (no requests to the target itself), which keeps it lightweight and
non-intrusive. A built-in short list is used unless a wordlist file is given.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors, utils

DEFAULT_WORDS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "dns",
    "admin", "portal", "vpn", "api", "dev", "staging", "test", "beta",
    "app", "blog", "shop", "store", "cdn", "static", "img", "assets",
    "secure", "login", "remote", "gateway", "git", "gitlab", "jenkins",
    "docs", "support", "help", "status", "monitor", "grafana", "kibana",
]


def _load_words(wordlist):
    if not wordlist:
        return DEFAULT_WORDS
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
        return words or DEFAULT_WORDS
    except OSError as e:
        print(colors.err(f"Could not read wordlist: {e}"))
        return DEFAULT_WORDS


def _resolve_sub(sub: str, domain: str):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except (socket.gaierror, socket.error):
        return None


def run(target: str, wordlist=None, workers: int = 50, logger=None):
    """Enumerate subdomains of ``target``. Returns list of (fqdn, ip)."""
    domain = utils.normalize_host(target)
    words = _load_words(wordlist)
    print(colors.info(f"Enumerating {len(words)} candidate subdomains for "
                      f"{colors.bold(domain)}"))
    if logger:
        logger.event("subdomain_enum", domain, f"candidates={len(words)}")

    found = []
    workers = max(1, min(workers, len(words)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_resolve_sub, w, domain) for w in words]
        try:
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    fqdn, ip = result
                    found.append(result)
                    print(colors.ok(f"{fqdn:<40} {ip}"))
        except KeyboardInterrupt:
            print(colors.warn("\nEnumeration interrupted by user."))

    found.sort()
    print(colors.info(f"{len(found)} subdomain(s) resolved."))
    if logger:
        logger.event("subdomain_enum", domain, f"found={len(found)}")
    return found
