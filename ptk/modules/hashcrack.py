"""Offline dictionary attack against a single unsalted hash.

Given a hash and a wordlist file, hashes each candidate word and compares.
Purely offline (no network, no live service) — intended for password auditing
and CTF practice on hashes you are authorized to test. Supports the common
unsalted hex digests: md5, sha1, sha224, sha256, sha384, sha512.

For anything beyond simple unsalted hashes (bcrypt, salted crypt, etc.) use a
dedicated cracker like John the Ripper or hashcat.
"""

import hashlib

from ..core import colors
from . import hashid

_LEN_TO_ALGOS = {
    32: ["md5"], 40: ["sha1"], 56: ["sha224"],
    64: ["sha256"], 96: ["sha384"], 128: ["sha512"],
}


def _candidate_algos(target_hash, override):
    if override:
        return [override]
    return _LEN_TO_ALGOS.get(len(target_hash.strip()), ["md5", "sha1", "sha256"])


def run(target_hash: str, wordlist: str, algo: str = None, logger=None):
    """Try to crack ``target_hash`` using ``wordlist``. Returns the word or None."""
    target_hash = target_hash.strip().lower()
    algos = _candidate_algos(target_hash, algo)
    print(colors.info(f"Dictionary attack — trying algorithm(s): {', '.join(algos)}"))
    print(colors.dim(f"  (hash looks like: {', '.join(hashid.identify(target_hash))})"))
    if logger:
        logger.event("hashcrack", target_hash[:16] + "...", f"algos={algos}")

    try:
        fh = open(wordlist, "r", encoding="utf-8", errors="ignore")
    except OSError as e:
        print(colors.err(f"Could not open wordlist: {e}"))
        return None

    tried = 0
    with fh:
        for line in fh:
            word = line.rstrip("\n")
            if not word:
                continue
            tried += 1
            wb = word.encode("utf-8")
            for a in algos:
                if hashlib.new(a, wb).hexdigest() == target_hash:
                    print(colors.ok(f"FOUND after {tried} candidate(s): "
                                    f"{colors.bold(word)}  ({a})"))
                    if logger:
                        logger.event("hashcrack", target_hash[:16] + "...", f"cracked algo={a}")
                    return word

    print(colors.warn(f"Not found in wordlist ({tried} candidate(s) tried)."))
    if logger:
        logger.event("hashcrack", target_hash[:16] + "...", f"not_found tried={tried}")
    return None
