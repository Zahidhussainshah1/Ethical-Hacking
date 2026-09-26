"""Passive web technology fingerprinting from headers and page body."""

import re

from ..core import colors, http

# (label, regex applied to lowercased body or header blob)
_SIGNATURES = [
    ("WordPress", re.compile(r"wp-content|wp-includes|/wp-json")),
    ("Drupal", re.compile(r"drupal|sites/default/files")),
    ("Joomla", re.compile(r"joomla|/media/jui/")),
    ("Magento", re.compile(r"mage/|magento")),
    ("Shopify", re.compile(r"cdn\.shopify\.com|shopify")),
    ("Django", re.compile(r"csrfmiddlewaretoken")),
    ("Laravel", re.compile(r"laravel_session|xsrf-token")),
    ("React", re.compile(r"react(?:\.min)?\.js|data-reactroot|__react")),
    ("Vue.js", re.compile(r"vue(?:\.min)?\.js|data-v-")),
    ("Angular", re.compile(r"ng-version|angular(?:\.min)?\.js")),
    ("jQuery", re.compile(r"jquery(?:[-.]\d|\.min)?\.js")),
    ("Bootstrap", re.compile(r"bootstrap(?:\.min)?\.(?:css|js)")),
    ("Cloudflare", re.compile(r"cloudflare|__cf_bm")),
    ("Nginx", re.compile(r"\bnginx\b")),
    ("Apache", re.compile(r"\bapache\b")),
]

_HEADER_HINTS = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
                 "X-Drupal-Cache", "X-Shopify-Stage", "Via"]


def run(target: str, timeout: float = 8.0, logger=None):
    """Fingerprint the technology stack of ``target``. Returns a dict."""
    url = http.base_url(target)
    print(colors.info(f"Fingerprinting {colors.bold(url)}"))
    if logger:
        logger.event("web_tech", url)

    try:
        resp = http.fetch(url, timeout=timeout)
    except (OSError, ValueError) as e:
        print(colors.err(f"Request failed: {e}"))
        return {}

    headers = {k: v for k, v in resp.headers.items()}
    body = http.read_body(resp)
    blob = (body + " " + " ".join(f"{k}:{v}" for k, v in headers.items())).lower()

    found = []
    for label, pat in _SIGNATURES:
        if pat.search(blob):
            found.append(label)

    header_facts = {h: headers[h] for h in _HEADER_HINTS if h in headers}

    for h, v in header_facts.items():
        print(colors.green(f"  {h}: {v}"))
    if found:
        print(colors.ok("Detected: " + ", ".join(found)))
    else:
        print(colors.warn("No known technology signatures matched."))

    result = {"technologies": found, "headers": header_facts}
    if logger:
        logger.event("web_tech", url, f"tech={found}")
    return result
