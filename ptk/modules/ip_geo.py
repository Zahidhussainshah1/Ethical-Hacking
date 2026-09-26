"""IP geolocation / ASN lookup via the public ip-api.com service (passive)."""

import json

from ..core import colors, http, utils

_FIELDS = ["query", "country", "regionName", "city", "isp", "org", "as",
           "reverse", "timezone"]


def run(target: str, timeout: float = 10.0, logger=None):
    """Geolocate ``target`` (host or IP). Returns a dict of location facts."""
    host = utils.normalize_host(target)
    ip = utils.resolve(host) or host
    url = f"http://ip-api.com/json/{ip}?fields={','.join(_FIELDS)}"
    print(colors.info(f"Geolocating {colors.bold(host)} ({ip})"))
    if logger:
        logger.event("ip_geo", host, f"ip={ip}")

    try:
        resp = http.fetch(url, timeout=timeout)
        data = json.loads(http.read_body(resp, 100_000))
    except (OSError, ValueError) as e:
        print(colors.err(f"Lookup failed: {e}"))
        return {}

    labels = {
        "country": "Country", "regionName": "Region", "city": "City",
        "isp": "ISP", "org": "Org", "as": "ASN", "reverse": "rDNS",
        "timezone": "Timezone",
    }
    for key, label in labels.items():
        if data.get(key):
            print(colors.ok(f"{label:<9} {data[key]}"))
    if logger:
        logger.event("ip_geo", host, f"country={data.get('country')}")
    return data
