"""DNS zone transfer (AXFR) check.

Attempts an AXFR against each authoritative name server for a domain. A
successful transfer is a common, high-value misconfiguration finding. Uses the
system ``dig`` binary (Termux: pkg install dnsutils).
"""

import shutil
import subprocess

from ..core import colors, utils


def _nameservers(domain: str):
    dig = shutil.which("dig")
    if not dig:
        return []
    try:
        out = subprocess.run([dig, "+short", "NS", domain],
                             capture_output=True, text=True, timeout=15)
        return [ns.strip().rstrip(".") for ns in out.stdout.splitlines() if ns.strip()]
    except (subprocess.SubprocessError, OSError):
        return []


def _axfr(domain: str, ns: str):
    dig = shutil.which("dig")
    try:
        out = subprocess.run([dig, f"@{ns}", domain, "AXFR", "+time=8", "+tries=1"],
                             capture_output=True, text=True, timeout=25)
        text = out.stdout
        if "Transfer failed" in text or "failed" in text.lower() or "connection timed out" in text.lower():
            return None
        records = [ln for ln in text.splitlines()
                   if ln and not ln.startswith(";") and "\t" in ln]
        return records or None
    except (subprocess.SubprocessError, OSError):
        return None


def run(target: str, logger=None):
    """Attempt AXFR for ``target`` against each of its name servers."""
    domain = utils.normalize_host(target)
    if not shutil.which("dig"):
        print(colors.err("'dig' not found. Install with: pkg install dnsutils"))
        return {}

    print(colors.info(f"Zone transfer check for {colors.bold(domain)}"))
    if logger:
        logger.event("zone_transfer", domain)

    servers = _nameservers(domain)
    if not servers:
        print(colors.warn("No name servers found."))
        return {}

    results = {}
    for ns in servers:
        print(colors.info(f"  Trying AXFR @ {ns} ..."))
        records = _axfr(domain, ns)
        if records:
            print(colors.err(f"  VULNERABLE: {ns} allowed zone transfer "
                             f"({len(records)} records)"))
            for r in records[:50]:
                print(colors.green(f"    {r}"))
            if len(records) > 50:
                print(colors.dim(f"    ... {len(records) - 50} more"))
            results[ns] = records
        else:
            print(colors.ok(f"  {ns} refused transfer (good)"))

    if logger:
        logger.event("zone_transfer", domain, f"vulnerable={list(results.keys())}")
    return results
