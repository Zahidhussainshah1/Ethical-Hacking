"""Offline password strength analyzer.

Estimates entropy from the character space and length, flags common weak
patterns, and gives a qualitative rating. Fully offline — nothing is sent
anywhere.
"""

import math
import re

from ..core import colors

_COMMON = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111",
    "12345678", "admin", "letmein", "welcome", "monkey", "dragon",
    "iloveyou", "000000", "password1", "qwerty123",
}


def _charset_size(pw):
    size = 0
    if re.search(r"[a-z]", pw): size += 26
    if re.search(r"[A-Z]", pw): size += 26
    if re.search(r"[0-9]", pw): size += 10
    if re.search(r"[^A-Za-z0-9]", pw): size += 33
    return size or 1


def _rating(bits):
    if bits < 28:   return "Very weak", colors.red
    if bits < 36:   return "Weak", colors.red
    if bits < 60:   return "Reasonable", colors.yellow
    if bits < 128:  return "Strong", colors.green
    return "Very strong", colors.green


def run(password: str, logger=None):
    """Analyze ``password`` strength. Returns a dict of findings."""
    pw = password
    length = len(pw)
    charset = _charset_size(pw)
    entropy = round(length * math.log2(charset), 1) if length else 0.0
    rating, color = _rating(entropy)

    warnings = []
    if pw.lower() in _COMMON:
        warnings.append("appears in common-password list")
    if length < 12:
        warnings.append("shorter than 12 characters")
    if re.fullmatch(r"[a-z]+|[0-9]+|[A-Z]+", pw or " "):
        warnings.append("single character class only")
    if re.search(r"(.)\1{2,}", pw):
        warnings.append("contains a repeated-character run")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", pw.lower()):
        warnings.append("contains a common sequence")

    print(colors.info("Password analysis"))
    print(colors.ok(f"Length     : {length}"))
    print(colors.ok(f"Char space : {charset}"))
    print(colors.ok(f"Entropy    : ~{entropy} bits"))
    print(color(f"Rating     : {rating}"))
    for w in warnings:
        print(colors.warn(f"  - {w}"))

    result = {"length": length, "entropy_bits": entropy, "rating": rating,
              "warnings": warnings}
    if logger:
        logger.event("pwcheck", f"len={length}", f"rating={rating}")
    return result
