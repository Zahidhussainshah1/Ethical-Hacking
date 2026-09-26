"""Offline hash generator for a given input string."""

import hashlib

from ..core import colors

_ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]


def run(text: str, logger=None):
    """Print common hash digests of ``text``. Returns a dict of algo -> hex."""
    data = text.encode("utf-8")
    print(colors.info(f"Hashing {len(data)} byte(s)"))
    out = {}
    for algo in _ALGOS:
        digest = hashlib.new(algo, data).hexdigest()
        out[algo] = digest
        print(colors.ok(f"{algo:<8} {digest}"))
    if logger:
        logger.event("hashgen", f"len={len(data)}")
    return out
