"""Offline multi-format encoder/decoder.

Supported: base64, base32, hex, url, rot13.
"""

import base64
import binascii
import codecs
import urllib.parse

from ..core import colors

_SCHEMES = ("base64", "base32", "hex", "url", "rot13")


def _encode(scheme, text):
    b = text.encode("utf-8")
    if scheme == "base64":
        return base64.b64encode(b).decode()
    if scheme == "base32":
        return base64.b32encode(b).decode()
    if scheme == "hex":
        return b.hex()
    if scheme == "url":
        return urllib.parse.quote(text, safe="")
    if scheme == "rot13":
        return codecs.encode(text, "rot_13")
    raise ValueError(scheme)


def _decode(scheme, text):
    if scheme == "base64":
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")
    if scheme == "base32":
        return base64.b32decode(text + "=" * (-len(text) % 8)).decode("utf-8", "replace")
    if scheme == "hex":
        return bytes.fromhex(text.strip()).decode("utf-8", "replace")
    if scheme == "url":
        return urllib.parse.unquote(text)
    if scheme == "rot13":
        return codecs.decode(text, "rot_13")
    raise ValueError(scheme)


def run(scheme: str, text: str, decode: bool = False, logger=None):
    """Encode (default) or decode ``text`` using ``scheme``."""
    scheme = scheme.lower().strip()
    if scheme not in _SCHEMES:
        print(colors.err(f"Unknown scheme '{scheme}'. Choices: {', '.join(_SCHEMES)}"))
        return None
    action = "decode" if decode else "encode"
    print(colors.info(f"{scheme} {action}"))
    try:
        result = _decode(scheme, text) if decode else _encode(scheme, text)
    except (binascii.Error, ValueError, UnicodeError) as e:
        print(colors.err(f"{action} failed: {e}"))
        return None
    print(colors.ok(result))
    if logger:
        logger.event("encoder", scheme, action)
    return result
