"""Passive URL discovery via the Wayback Machine (web.archive.org CDX API)."""

import json

from ..core import colors, http, utils


def run(target: str, limit: int = 500, timeout: float = 25.0, logger=None):
    """Fetch known historical URLs for ``target``. Returns a list of URLs."""
    domain = utils.normalize_host(target)
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={int(limit)}")
    print(colors.info(f"Querying Wayback Machine for {colors.bold(domain)}"))
    if logger:
        logger.event("wayback", domain)

    try:
        resp = http.fetch(url, timeout=timeout)
        rows = json.loads(http.read_body(resp, 5_000_000))
    except (OSError, ValueError) as e:
        print(colors.err(f"Wayback query failed: {e}"))
        return []

    # First row is the header (["original"]).
    urls = sorted({r[0] for r in rows[1:] if r})
    for u in urls[:200]:
        print(colors.green(f"  {u}"))
    if len(urls) > 200:
        print(colors.dim(f"  ... {len(urls) - 200} more"))
    print(colors.info(f"{len(urls)} archived URL(s)."))
    if logger:
        logger.event("wayback", domain, f"urls={len(urls)}")
    return urls
