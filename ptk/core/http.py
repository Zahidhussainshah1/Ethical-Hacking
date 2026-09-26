"""Shared HTTP helper built on the standard library (no requests dependency)."""

import ssl
import urllib.error
import urllib.request

USER_AGENT = "PTK/0.2 (+authorized-testing)"

# Permissive context: recon should still work against hosts with imperfect
# certificate chains. We are inspecting, not trusting.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def fetch(url, timeout=8.0, headers=None, method="GET", data=None):
    """Return an HTTP response object (or an HTTPError, which also has headers).

    Raises URLError/OSError on connection-level failures.
    """
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method=method, data=data)
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=_CTX)
    except urllib.error.HTTPError as e:
        return e  # still exposes .status, .headers, .read()


def read_body(resp, limit=200_000):
    try:
        return resp.read(limit).decode("utf-8", errors="replace")
    except (OSError, AttributeError):
        return ""


def base_url(target):
    """Turn a host or URL into a base URL, defaulting to https://."""
    target = target.strip().rstrip("/")
    if "://" in target:
        return target
    return "https://" + target
