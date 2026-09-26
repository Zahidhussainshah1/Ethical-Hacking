"""TLS/SSL certificate and connection inspector."""

import datetime
import socket
import ssl

from ..core import colors, utils


def _fmt_name(pairs):
    """Flatten the nested tuple structure returned by getpeercert()."""
    out = {}
    for rdn in pairs or ():
        for key, val in rdn:
            out[key] = val
    return out


def run(target: str, port: int = 443, timeout: float = 8.0, logger=None):
    """Connect over TLS and report certificate + negotiated parameters."""
    host = utils.normalize_host(target)
    print(colors.info(f"TLS inspection of {colors.bold(host)}:{port}"))
    if logger:
        logger.event("tls_info", host, f"port={port}")

    ctx = ssl.create_default_context()
    # Report on the cert even if the chain/hostname doesn't validate.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    info = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                cipher = ssock.cipher()
                info["cipher"] = cipher[0] if cipher else None
    except (socket.error, ssl.SSLError, OSError) as e:
        print(colors.err(f"TLS connection failed: {e}"))
        return {}

    print(colors.ok(f"Protocol: {info['protocol']}   Cipher: {info['cipher']}"))

    if cert:
        subj = _fmt_name(cert.get("subject"))
        issuer = _fmt_name(cert.get("issuer"))
        info["subject"] = subj
        info["issuer"] = issuer
        info["not_before"] = cert.get("notBefore")
        info["not_after"] = cert.get("notAfter")
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        info["san"] = sans

        print(colors.ok(f"Subject CN: {subj.get('commonName', '?')}"))
        print(colors.ok(f"Issuer   : {issuer.get('organizationName', issuer.get('commonName', '?'))}"))
        print(colors.ok(f"Valid    : {cert.get('notBefore')}  ->  {cert.get('notAfter')}"))

        # Expiry check.
        try:
            exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            if days < 0:
                print(colors.err(f"Certificate EXPIRED {abs(days)} day(s) ago"))
            elif days < 30:
                print(colors.warn(f"Certificate expires in {days} day(s)"))
            else:
                print(colors.info(f"Certificate valid for {days} more day(s)"))
            info["days_remaining"] = days
        except (ValueError, KeyError):
            pass

        if sans:
            print(colors.info(f"SAN: {', '.join(sans[:15])}"
                              + (" ..." if len(sans) > 15 else "")))
    else:
        print(colors.warn("No certificate details returned (self-signed or verify disabled)."))

    if logger:
        logger.event("tls_info", host, f"proto={info.get('protocol')}")
    return info
