"""Web content discovery (directory/file enumeration).

Requests each path from a wordlist and reports responses that are not 404.
This is standard content discovery for authorized web assessments; it is an
ACTIVE module and is gated behind the authorization prompt.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors, http

DEFAULT_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "dashboard",
    "phpmyadmin", "config", "config.php", ".env", ".git/HEAD", ".git/config",
    "backup", "backups", "backup.zip", "backup.sql", "db.sql", "dump.sql",
    "api", "api/v1", "swagger", "swagger.json", "openapi.json", "graphql",
    "robots.txt", "sitemap.xml", ".htaccess", "server-status", "status",
    "test", "dev", "staging", "old", "tmp", "temp", "uploads", "files",
    "images", "assets", "static", "js", "css", "includes", "vendor",
    "readme", "README.md", "CHANGELOG.md", "license.txt", "info.php",
    "phpinfo.php", "console", "actuator", "actuator/health", "metrics",
    "debug", "hidden", "private", "secret", "internal", "cgi-bin",
]

_INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}


def _load(wordlist):
    if not wordlist:
        return DEFAULT_PATHS
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
        return words or DEFAULT_PATHS
    except OSError as e:
        print(colors.err(f"Wordlist error: {e}"))
        return DEFAULT_PATHS


def _probe(base, path, timeout):
    url = f"{base}/{path.lstrip('/')}"
    try:
        resp = http.fetch(url, timeout=timeout, method="GET")
        status = getattr(resp, "status", getattr(resp, "code", 0))
        length = resp.headers.get("Content-Length", "?")
        if status in _INTERESTING:
            return path, status, length
    except (OSError, ValueError):
        return None
    return None


def run(target: str, wordlist=None, timeout: float = 6.0, workers: int = 30, logger=None):
    """Enumerate paths on ``target``. Returns list of (path, status, length)."""
    base = http.base_url(target)
    paths = _load(wordlist)
    print(colors.info(f"Content discovery on {colors.bold(base)} — {len(paths)} paths"))
    if logger:
        logger.event("dir_enum", base, f"paths={len(paths)}")

    found = []
    workers = max(1, min(workers, len(paths)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe, base, p, timeout) for p in paths]
        try:
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    path, status, length = res
                    found.append(res)
                    color = colors.green if status < 400 else colors.yellow
                    print(color(f"  {status}  /{path}  (len {length})"))
        except KeyboardInterrupt:
            print(colors.warn("\nInterrupted."))

    found.sort(key=lambda r: (r[1], r[0]))
    print(colors.info(f"{len(found)} interesting response(s)."))
    if logger:
        logger.event("dir_enum", base, f"found={len(found)}")
    return found
