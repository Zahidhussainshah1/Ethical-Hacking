"""Targeted wordlist generator from a set of base keywords.

Produces case variants, common leet substitutions, and appended
years/suffixes. Useful for building custom candidate lists during authorized
assessments (e.g. seeding a subdomain or content-discovery run).
"""

from ..core import colors

_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})
_SUFFIXES = ["", "1", "12", "123", "1234", "!", "@", "#", "2023", "2024",
             "2025", "01", "007", "admin", "_"]


def _case_variants(word):
    return {word.lower(), word.upper(), word.capitalize()}


def generate(keywords, use_leet=True, max_items=5000):
    out = set()
    for kw in keywords:
        kw = kw.strip()
        if not kw:
            continue
        bases = _case_variants(kw)
        if use_leet:
            bases |= {b.translate(_LEET) for b in bases}
        for base in bases:
            for suf in _SUFFIXES:
                out.add(base + suf)
                if len(out) >= max_items:
                    return sorted(out)
    return sorted(out)


def run(keywords, outfile=None, use_leet: bool = True, logger=None):
    """Generate a wordlist from comma/space-separated ``keywords``."""
    if isinstance(keywords, str):
        keywords = [k for k in keywords.replace(",", " ").split() if k]
    words = generate(keywords, use_leet=use_leet)
    print(colors.info(f"Generated {len(words)} candidate(s) from {len(keywords)} keyword(s)"))

    if outfile:
        try:
            with open(outfile, "w", encoding="utf-8") as fh:
                fh.write("\n".join(words) + "\n")
            print(colors.ok(f"Written to {outfile}"))
        except OSError as e:
            print(colors.err(f"Write failed: {e}"))
    else:
        for w in words[:60]:
            print(colors.green(f"  {w}"))
        if len(words) > 60:
            print(colors.dim(f"  ... {len(words) - 60} more (use --out to save all)"))

    if logger:
        logger.event("wordlist_gen", f"kw={len(keywords)}", f"generated={len(words)}")
    return words
