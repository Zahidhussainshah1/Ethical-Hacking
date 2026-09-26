"""Offline subnet / CIDR calculator."""

import ipaddress

from ..core import colors


def run(cidr: str, logger=None):
    """Print network details for a CIDR (e.g. 10.0.0.0/24). Returns a dict."""
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        print(colors.err(f"Invalid CIDR: {e}"))
        return {}

    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    info = {
        "network": str(net.network_address),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "broadcast": str(net.broadcast_address) if net.version == 4 else "n/a",
        "prefix": f"/{net.prefixlen}",
        "total_addresses": net.num_addresses,
        "usable_hosts": len(hosts),
        "first_host": str(hosts[0]) if hosts else "n/a",
        "last_host": str(hosts[-1]) if hosts else "n/a",
    }
    print(colors.info(f"Subnet details for {colors.bold(str(net))}"))
    for key, val in info.items():
        print(colors.ok(f"{key.replace('_', ' ').title():<16} {val}"))
    if logger:
        logger.event("subnet", str(net))
    return info
