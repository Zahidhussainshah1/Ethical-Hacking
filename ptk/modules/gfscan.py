"""gf-style pattern triage for URL lists (offline).

Scans a list of URLs and groups those whose query parameters look prone to a
given vulnerability class (open redirect, SSRF, LFI, SQLi, XSS, SSTI, IDOR).
This is a TRIAGE aid — it flags candidates worth manual review, it does not
test or exploit anything. Fully offline.
"""

from urllib.parse import parse_qs, urlparse

from ..core import colors, utils

# class -> set of suspicious parameter-name substrings
_PATTERNS = {
    "redirect": ["url", "redirect", "next", "return", "returnurl", "returnto",
                 "goto", "dest", "destination", "redir", "rurl", "continue", "target"],
    "ssrf": ["url", "uri", "path", "dest", "domain", "callback", "webhook",
             "fetch", "site", "host", "port", "to", "out", "view", "image", "img"],
    "lfi": ["file", "filename", "path", "page", "document", "folder", "root",
            "pg", "template", "include", "inc", "dir", "download", "load"],
    "sqli": ["id", "select", "report", "search", "category", "cat", "user",
             "username", "order", "sort", "where", "query", "q", "record"],
    "xss": ["q", "search", "query", "s", "keyword", "lang", "name", "message",
            "comment", "redirect", "return", "callback", "input"],
    "ssti": ["template", "preview", "id", "view", "activity", "name", "content"],
    "idor": ["id", "user", "uid", "account", "number", "order", "no", "doc",
             "file", "key", "profile", "customer", "invoice"],
}


def run(source, vuln_class: str = "all", logger=None):
    """Flag URLs in ``source`` with params matching ``vuln_class`` (or 'all')."""
    vuln_class = (vuln_class or "all").lower()
    classes = list(_PATTERNS) if vuln_class == "all" else [vuln_class]
    for c in classes:
        if c not in _PATTERNS:
            print(colors.err(f"Unknown class '{c}'. Choices: all, {', '.join(_PATTERNS)}"))
            return {}

    urls = utils.read_list(source)
    if not urls:
        print(colors.err("No input URLs."))
        return {}
    print(colors.info(f"Triaging {len(urls)} URL(s) for: {', '.join(classes)}"))

    results = {c: [] for c in classes}
    for u in urls:
        try:
            params = set(parse_qs(urlparse(u if "://" in u else "http://" + u).query))
        except ValueError:
            continue
        if not params:
            continue
        low = {p.lower() for p in params}
        for c in classes:
            hit = low & set(_PATTERNS[c])
            if hit:
                results[c].append((u, sorted(hit)))

    total = 0
    for c in classes:
        if results[c]:
            print(colors.bold(colors.magenta(f"\n[{c}]")))
            for url, keys in results[c]:
                total += 1
                print(colors.yellow(f"  {url}") + colors.dim(f"   (params: {', '.join(keys)})"))
    if total == 0:
        print(colors.ok("No candidate URLs matched."))
    else:
        print(colors.info(f"\n{total} candidate URL(s) flagged for manual review."))
    if logger:
        logger.event("gfscan", f"class={vuln_class}", f"flagged={total}")
    return results
