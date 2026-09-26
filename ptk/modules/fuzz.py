"""ffuf/gobuster-style FUZZ-keyword fuzzer (pure Python).

Replaces the literal keyword ``FUZZ`` in a URL with each entry of a wordlist
and reports responses, with optional status-code and content-length filters.
Works anywhere in the URL (path, query value, subdomain), so it covers content
discovery and parameter/value fuzzing. ACTIVE module — authorization-gated.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import colors, http


def _load(wordlist):
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            return [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    except OSError as e:
        print(colors.err(f"Wordlist error: {e}"))
        return []


def _req(url, timeout):
    try:
        resp = http.fetch(url, timeout=timeout)
        status = getattr(resp, "status", getattr(resp, "code", 0))
        body = http.read_body(resp, 200_000)
        return status, len(body)
    except (OSError, ValueError):
        return None


def run(url, wordlist, timeout: float = 6.0, workers: int = 30,
        match_codes=None, filter_len=None, logger=None):
    """Fuzz ``url`` (must contain FUZZ) with ``wordlist``. Returns list of hits."""
    if "FUZZ" not in url:
        print(colors.err("URL must contain the FUZZ keyword, e.g. https://site/FUZZ"))
        return []
    words = _load(wordlist)
    if not words:
        return []

    # Default: hide 404s.
    match_codes = set(match_codes) if match_codes else None
    print(colors.info(f"Fuzzing {colors.bold(url)} with {len(words)} payload(s)"))
    if logger:
        logger.event("fuzz", url, f"words={len(words)}")

    hits = []
    workers = max(1, min(workers, len(words)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_req, url.replace("FUZZ", w), timeout): w for w in words}
        try:
            for fut in as_completed(futures):
                word = futures[fut]
                res = fut.result()
                if not res:
                    continue
                status, length = res
                if match_codes is not None and status not in match_codes:
                    continue
                if match_codes is None and status == 404:
                    continue
                if filter_len is not None and length == filter_len:
                    continue
                hits.append({"payload": word, "status": status, "length": length})
                col = colors.green if status < 400 else colors.yellow
                print(col(f"  {status}  {word}  (len {length})"))
        except KeyboardInterrupt:
            print(colors.warn("\nInterrupted."))

    print(colors.info(f"{len(hits)} hit(s)."))
    if logger:
        logger.event("fuzz", url, f"hits={len(hits)}")
    return hits
