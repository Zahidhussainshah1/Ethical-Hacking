"""Offline hash-type identifier based on length and character class."""

import re

from ..core import colors

_HEX = re.compile(r"^[a-fA-F0-9]+$")


def identify(value: str):
    """Return a list of likely hash types for ``value``."""
    v = value.strip()
    guesses = []

    if v.startswith("$2a$") or v.startswith("$2b$") or v.startswith("$2y$"):
        guesses.append("bcrypt")
    if v.startswith("$1$"):
        guesses.append("MD5 crypt")
    if v.startswith("$5$"):
        guesses.append("SHA-256 crypt")
    if v.startswith("$6$"):
        guesses.append("SHA-512 crypt")
    if v.startswith("$argon2"):
        guesses.append("Argon2")
    if re.match(r"^[A-Za-z0-9./]{13}$", v) and "$" not in v:
        guesses.append("DES crypt (traditional)")

    if _HEX.match(v):
        by_len = {
            32: ["MD5", "NTLM", "MD4"],
            40: ["SHA-1"],
            56: ["SHA-224"],
            64: ["SHA-256"],
            96: ["SHA-384"],
            128: ["SHA-512"],
            16: ["MySQL (pre-4.1)", "CRC-64"],
        }
        guesses.extend(by_len.get(len(v), []))

    if not guesses:
        guesses.append("unknown")
    return guesses


def run(value: str, logger=None):
    """Identify the likely hash type(s) of ``value``."""
    print(colors.info(f"Identifying hash ({len(value.strip())} chars)"))
    guesses = identify(value)
    for g in guesses:
        print(colors.ok(g))
    if logger:
        logger.event("hashid", value[:16] + "...", f"guesses={guesses}")
    return guesses
