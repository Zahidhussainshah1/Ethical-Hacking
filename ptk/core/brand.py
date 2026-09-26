"""Central branding for PTK — single source of truth.

All user-facing branding (banner, report footers, CLI headers) reads from the
constants here so the attribution stays consistent everywhere.

NOTE ON "UN-REMOVABLE" BRANDING
-------------------------------
This is open-source software: anyone with the source can edit any string,
including these constants. The integrity check below can *detect* casual
tampering and re-assert the brand at runtime, but it cannot truly prevent a
determined person from editing the code — no client-side check can. The real,
enforceable protection for a brand name is trademark + the license terms, not
code. Treat this module as "make the branding prominent and hard to remove by
accident", not as DRM.
"""

import hashlib

# --------------------------------------------------------------------------- #
# Brand constants (edit here — everything else references these).
# --------------------------------------------------------------------------- #
VENDOR = "BitCops"
URL = "https://bitcops.net"
TAGLINE = "Offensive security tooling"

# Canonical values kept separately so verify() can restore them even if the
# public constants above are blanked or edited.
_CANON_VENDOR = "BitCops"
_CANON_URL = "https://bitcops.net"


def _fingerprint(vendor: str, url: str) -> str:
    return hashlib.sha256(f"{vendor}|{url}".encode()).hexdigest()[:8]


def line() -> str:
    """One-line brand attribution, e.g. 'BitCops · https://bitcops.net'."""
    return f"{VENDOR} · {URL}"


def verify() -> bool:
    """Return True if branding is intact; if tampered, re-assert canonical values.

    This is a best-effort integrity aid, not tamper-proofing (see module note).
    """
    global VENDOR, URL
    intact = _fingerprint(VENDOR, URL) == _SEAL
    if not intact:
        VENDOR, URL = _CANON_VENDOR, _CANON_URL
    return intact


# Seal computed from the canonical values at import time. verify() compares the
# live VENDOR/URL against this; a mismatch means the public constants were
# edited, and verify() re-asserts the canonical branding.
_SEAL = _fingerprint(_CANON_VENDOR, _CANON_URL)
