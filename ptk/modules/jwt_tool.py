"""Offline JWT decoder / inspector.

Decodes and pretty-prints the header and payload of a JSON Web Token and flags
common weaknesses (alg=none, HS256 where RS256 may be expected, missing exp).
It does NOT crack or forge signatures — it is an inspection aid only.
"""

import base64
import datetime
import json

from ..core import colors


def _b64url_decode(segment: str) -> bytes:
    segment += "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def run(token: str, logger=None):
    """Decode ``token`` (header.payload.signature). Returns dict of parts."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) not in (2, 3):
        print(colors.err("Not a JWT (expected 2-3 dot-separated segments)."))
        return None

    result = {}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as e:
        print(colors.err(f"Failed to decode JWT: {e}"))
        return None

    result["header"] = header
    result["payload"] = payload

    print(colors.ok("Header:"))
    print(colors.green("  " + json.dumps(header, indent=2).replace("\n", "\n  ")))
    print(colors.ok("Payload:"))
    print(colors.green("  " + json.dumps(payload, indent=2).replace("\n", "\n  ")))

    # Weakness notes.
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        print(colors.err("  alg=none — signature not verified (critical if accepted)"))
    if alg.startswith("hs"):
        print(colors.warn("  Symmetric alg (HS*) — forgeable if the secret is weak/known"))

    for claim in ("exp", "nbf", "iat"):
        if claim in payload:
            try:
                dt = datetime.datetime.utcfromtimestamp(int(payload[claim]))
                note = ""
                if claim == "exp" and dt < datetime.datetime.utcnow():
                    note = colors.err(" (EXPIRED)")
                print(colors.info(f"  {claim}: {dt} UTC{note}"))
            except (ValueError, OSError, TypeError):
                pass
    if "exp" not in payload:
        print(colors.warn("  No 'exp' claim — token may never expire"))

    if logger:
        logger.event("jwt_tool", alg or "?", "decoded")
    return result
