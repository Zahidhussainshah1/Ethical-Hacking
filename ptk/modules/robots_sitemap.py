"""Fetch and parse robots.txt and sitemap.xml for interesting paths."""

import re

from ..core import colors, http

_SITEMAP_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def run(target: str, timeout: float = 8.0, logger=None):
    """Retrieve robots.txt / sitemap.xml. Returns dict with paths + sitemaps."""
    base = http.base_url(target)
    print(colors.info(f"Fetching robots.txt / sitemap.xml for {colors.bold(base)}"))
    if logger:
        logger.event("robots_sitemap", base)

    result = {"disallow": [], "allow": [], "sitemaps": [], "urls": []}

    # robots.txt
    try:
        resp = http.fetch(base + "/robots.txt", timeout=timeout)
        status = getattr(resp, "status", getattr(resp, "code", 0))
        if status == 200:
            body = http.read_body(resp, 100_000)
            for line in body.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("disallow:"):
                    result["disallow"].append(line.split(":", 1)[1].strip())
                elif low.startswith("allow:"):
                    result["allow"].append(line.split(":", 1)[1].strip())
                elif low.startswith("sitemap:"):
                    result["sitemaps"].append(line.split(":", 1)[1].strip())
            print(colors.ok(f"robots.txt: {len(result['disallow'])} Disallow, "
                            f"{len(result['allow'])} Allow entries"))
            for d in result["disallow"][:40]:
                print(colors.green(f"  Disallow: {d}"))
        else:
            print(colors.warn(f"robots.txt -> HTTP {status}"))
    except (OSError, ValueError) as e:
        print(colors.warn(f"robots.txt fetch failed: {e}"))

    # sitemap.xml
    sitemap_urls = result["sitemaps"] or [base + "/sitemap.xml"]
    for sm in sitemap_urls[:5]:
        try:
            resp = http.fetch(sm, timeout=timeout)
            status = getattr(resp, "status", getattr(resp, "code", 0))
            if status == 200:
                body = http.read_body(resp)
                locs = _SITEMAP_RE.findall(body)
                result["urls"].extend(locs)
                print(colors.ok(f"sitemap {sm}: {len(locs)} URL(s)"))
                for u in locs[:30]:
                    print(colors.green(f"  {u}"))
        except (OSError, ValueError):
            continue

    if logger:
        logger.event("robots_sitemap", base,
                     f"disallow={len(result['disallow'])} urls={len(result['urls'])}")
    return result
