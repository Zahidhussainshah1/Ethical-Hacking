"""Passive subdomain discovery via Certificate Transparency logs (crt.sh).

Queries the public crt.sh API — no traffic is sent to the target itself, so
this is a passive OSINT source.
"""

import json

from ..core import colors, http, utils


def run(target: str, timeout: float = 20.0, logger=None):
    """Find subdomains of ``target`` from CT logs. Returns a sorted list."""
    domain = utils.normalize_host(target)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    print(colors.info(f"Querying Certificate Transparency logs for {colors.bold(domain)}"))
    if logger:
        logger.event("crtsh", domain)

    try:
        resp = http.fetch(url, timeout=timeout)
        body = http.read_body(resp, 5_000_000)
        data = json.loads(body)
    except (OSError, ValueError) as e:
        print(colors.err(f"crt.sh query failed: {e}"))
        return []

    subs = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                subs.add(name)

    subs = sorted(subs)
    for s in subs:
        print(colors.ok(s))
    print(colors.info(f"{len(subs)} unique name(s) from CT logs."))
    if logger:
        logger.event("crtsh", domain, f"found={len(subs)}")
    return subs
