"""httpx-style HTTP prober (pure Python).

Takes one target or a file of targets, probes HTTPS then HTTP, and reports
status code, page title, Server header, content length, and final URL after
redirects. Multi-threaded. A pure-Python, no-root alternative to Go's httpx /
httprobe for Termux.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors, http, utils

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _probe_one(target, timeout):
    target = target.strip()
    candidates = [target] if "://" in target else [f"https://{target}", f"http://{target}"]
    for url in candidates:
        try:
            resp = http.fetch(url, timeout=timeout)
        except (OSError, ValueError):
            continue
        status = getattr(resp, "status", getattr(resp, "code", 0))
        server = resp.headers.get("Server", "")
        clen = resp.headers.get("Content-Length", "")
        final = getattr(resp, "url", url)
        title = ""
        ctype = resp.headers.get("Content-Type", "")
        if "html" in ctype.lower() or not ctype:
            m = _TITLE_RE.search(http.read_body(resp, 100_000))
            if m:
                title = " ".join(m.group(1).split())[:80]
        return {"url": final, "input": url, "status": status, "server": server,
                "length": clen, "title": title}
    return None


def run(target, timeout: float = 8.0, workers: int = 40, logger=None):
    """Probe ``target`` (a host/URL or a file of them). Returns list of dicts."""
    targets = utils.read_list(target)
    if not targets:
        print(colors.err("No targets to probe."))
        return []

    print(colors.info(f"Probing {len(targets)} target(s)"))
    if logger:
        logger.event("probe", f"n={len(targets)}")

    results = []
    workers = max(1, min(workers, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_one, t, timeout): t for t in targets}
        try:
            for fut in as_completed(futures):
                r = fut.result()
                if not r:
                    continue
                results.append(r)
                code = r["status"]
                col = colors.green if code < 400 else (colors.yellow if code < 500 else colors.red)
                extra = []
                if r["title"]:
                    extra.append(f"[{r['title']}]")
                if r["server"]:
                    extra.append(f"[{r['server']}]")
                if r["length"]:
                    extra.append(f"[{r['length']}b]")
                print(f"{col(r['url'])} {col('[' + str(code) + ']')} {' '.join(extra)}")
        except KeyboardInterrupt:
            print(colors.warn("\nInterrupted."))

    print(colors.info(f"{len(results)} live host(s)."))
    if logger:
        logger.event("probe", f"n={len(targets)}", f"live={len(results)}")
    return results
