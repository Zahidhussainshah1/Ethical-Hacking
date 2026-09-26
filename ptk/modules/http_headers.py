"""HTTP header / fingerprint grabber using only the standard library."""

import ssl
import urllib.error
import urllib.request

from ..core import colors, utils

_INTERESTING = [
    "Server", "X-Powered-By", "X-AspNet-Version", "Via", "X-Frame-Options",
    "Content-Security-Policy", "Strict-Transport-Security", "Set-Cookie",
    "X-Content-Type-Options", "Referrer-Policy", "Location",
]

_USER_AGENT = "PTK/0.1 (+authorized-testing)"


def _fetch(url: str, timeout: float):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="GET")
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def run(target: str, timeout: float = 8.0, logger=None):
    """Fetch a URL and report status + security-relevant response headers."""
    target = target.strip()
    if "://" not in target:
        host = utils.normalize_host(target)
        candidates = [f"https://{host}", f"http://{host}"]
    else:
        candidates = [target]

    print(colors.info(f"Grabbing HTTP headers for {colors.bold(candidates[0])}"))
    if logger:
        logger.event("http_headers", candidates[0])

    resp = None
    used = None
    last_err = None
    for url in candidates:
        try:
            resp = _fetch(url, timeout)
            used = url
            break
        except urllib.error.HTTPError as e:
            # An HTTP error still carries headers worth reporting.
            resp = e
            used = url
            break
        except (urllib.error.URLError, OSError, ValueError) as e:
            last_err = e
            continue

    if resp is None:
        print(colors.err(f"Request failed: {last_err}"))
        return {}

    status = getattr(resp, "status", None) or getattr(resp, "code", "?")
    print(colors.ok(f"{used} -> HTTP {status}"))

    headers = {k: v for k, v in resp.headers.items()}
    shown = {}
    for name in _INTERESTING:
        if name in headers:
            shown[name] = headers[name]
            print(colors.green(f"  {name}: {headers[name]}"))

    missing = [h for h in ("Content-Security-Policy", "Strict-Transport-Security",
                           "X-Frame-Options", "X-Content-Type-Options")
               if h not in headers]
    if missing:
        print(colors.warn(f"  Missing security headers: {', '.join(missing)}"))

    if logger:
        logger.event("http_headers", used, f"status={status}")
    return {"status": status, "headers": headers, "missing_security": missing}
