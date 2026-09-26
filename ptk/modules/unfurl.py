"""unfurl-style URL parser (offline).

Pulls apart a list of URLs and extracts a chosen component: domains, apex
domains, paths, query parameter keys, or full key=value pairs. Handy for
building and cleaning bug-bounty URL pipelines. Fully offline.
"""

from urllib.parse import parse_qsl, urlparse

from ..core import colors, utils

_MODES = ("domains", "apexes", "paths", "params", "keys", "values")


def _apex(host):
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _extract(url, mode):
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return []
    if mode == "domains":
        return [p.hostname] if p.hostname else []
    if mode == "apexes":
        return [_apex(p.hostname)] if p.hostname else []
    if mode == "paths":
        return [p.path] if p.path and p.path != "/" else []
    qs = parse_qsl(p.query, keep_blank_values=True)
    if mode == "params":
        return [f"{k}={v}" for k, v in qs]
    if mode == "keys":
        return [k for k, _ in qs]
    if mode == "values":
        return [v for _, v in qs]
    return []


def run(source, mode: str = "domains", logger=None):
    """Extract ``mode`` from each URL in ``source`` (a URL or a file). Returns sorted uniques."""
    mode = (mode or "domains").lower()
    if mode not in _MODES:
        print(colors.err(f"Unknown mode '{mode}'. Choices: {', '.join(_MODES)}"))
        return []
    urls = utils.read_list(source)
    if not urls:
        print(colors.err("No input URLs."))
        return []

    out = set()
    for u in urls:
        out.update(x for x in _extract(u, mode) if x)
    out = sorted(out)
    for item in out:
        print(colors.green(item))
    print(colors.info(f"{len(out)} unique {mode}."))
    if logger:
        logger.event("unfurl", f"mode={mode}", f"in={len(urls)} out={len(out)}")
    return out
