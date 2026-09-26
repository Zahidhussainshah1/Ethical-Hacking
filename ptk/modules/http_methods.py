"""Enumerate allowed HTTP methods on a URL.

Reads the Allow header from an OPTIONS request and highlights risky methods
(PUT, DELETE, TRACE, CONNECT, PATCH) that may indicate misconfiguration.
"""

from ..core import colors, http

_RISKY = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def run(target: str, timeout: float = 8.0, logger=None):
    """Report allowed HTTP methods for ``target``. Returns a dict."""
    url = http.base_url(target)
    print(colors.info(f"Checking allowed HTTP methods for {colors.bold(url)}"))
    if logger:
        logger.event("http_methods", url)

    allow = ""
    try:
        resp = http.fetch(url, timeout=timeout, method="OPTIONS")
        allow = resp.headers.get("Allow", "") or resp.headers.get("access-control-allow-methods", "")
    except (OSError, ValueError) as e:
        print(colors.err(f"OPTIONS request failed: {e}"))
        return {}

    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    if not methods:
        print(colors.warn("Server did not return an Allow header."))
        return {"methods": [], "risky": []}

    risky = [m for m in methods if m in _RISKY]
    print(colors.ok("Allowed: " + ", ".join(methods)))
    if risky:
        print(colors.warn("Potentially risky methods enabled: " + ", ".join(risky)))

    if logger:
        logger.event("http_methods", url, f"methods={methods}")
    return {"methods": methods, "risky": risky}
