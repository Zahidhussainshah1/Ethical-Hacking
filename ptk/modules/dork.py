"""Offline search-engine dork query generator (OSINT helper).

Builds useful Google/Bing search queries for a target domain. It does NOT run
any searches — it only prints ready-to-paste query strings.
"""

from ..core import colors

_TEMPLATES = [
    'site:{d}',
    'site:{d} -www',
    'site:{d} ext:pdf OR ext:doc OR ext:xls OR ext:txt',
    'site:{d} inurl:admin OR inurl:login OR inurl:dashboard',
    'site:{d} intitle:"index of"',
    'site:{d} inurl:wp-content OR inurl:wp-admin',
    'site:{d} ext:sql OR ext:env OR ext:log OR ext:bak OR ext:config',
    'site:{d} "api_key" OR "apikey" OR "secret" OR "password"',
    'site:pastebin.com "{d}"',
    'site:github.com "{d}"',
    'site:{d} inurl:"?id=" OR inurl:"?page=" OR inurl:"?file="',
    'intext:"{d}" filetype:xls OR filetype:csv',
]


def run(domain: str, logger=None):
    """Print a set of search dorks for ``domain``. Returns the list."""
    domain = domain.strip()
    print(colors.info(f"Search dorks for {colors.bold(domain)} (paste into a search engine):"))
    queries = [t.format(d=domain) for t in _TEMPLATES]
    for q in queries:
        print(colors.green(f"  {q}"))
    if logger:
        logger.event("dork", domain, f"count={len(queries)}")
    return queries
