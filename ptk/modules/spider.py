"""Shallow, same-domain web crawler for link/endpoint discovery."""

import re
from urllib.parse import urljoin, urlparse

from ..core import colors, http

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)


def _same_host(url, host):
    try:
        return urlparse(url).hostname == host
    except ValueError:
        return False


def _extract(base_url, body):
    links = set()
    for match in _LINK_RE.findall(body):
        links.add(urljoin(base_url, match))
    return links


def run(target: str, depth: int = 1, max_pages: int = 40, timeout: float = 8.0, logger=None):
    """Crawl ``target`` up to ``depth`` levels, same-domain only.

    Returns the sorted set of discovered same-domain URLs.
    """
    start = http.base_url(target)
    host = urlparse(start).hostname
    print(colors.info(f"Spidering {colors.bold(start)} (depth={depth}, max {max_pages} pages)"))
    if logger:
        logger.event("spider", start, f"depth={depth}")

    seen = set()
    found = set()
    frontier = [(start, 0)]

    while frontier and len(seen) < max_pages:
        url, d = frontier.pop(0)
        if url in seen or d > depth:
            continue
        seen.add(url)
        try:
            resp = http.fetch(url, timeout=timeout)
            body = http.read_body(resp, 300_000)
        except (OSError, ValueError):
            continue
        for link in _extract(url, body):
            if _same_host(link, host):
                if link not in found:
                    found.add(link)
                    print(colors.green(f"  {link}"))
                if d + 1 <= depth and link not in seen:
                    frontier.append((link, d + 1))

    result = sorted(found)
    print(colors.info(f"{len(result)} same-domain URL(s) from {len(seen)} page(s)."))
    if logger:
        logger.event("spider", start, f"urls={len(result)}")
    return result
