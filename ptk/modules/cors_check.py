"""CORS misconfiguration check.

Sends requests with crafted Origin headers and inspects the
Access-Control-Allow-Origin / -Allow-Credentials response headers for common
misconfigurations (origin reflection, wildcard-with-credentials, null origin).
"""

from ..core import colors, http

_EVIL = "https://evil.example.com"


def _probe(url, origin, timeout):
    try:
        resp = http.fetch(url, timeout=timeout, headers={"Origin": origin})
        h = resp.headers
        return h.get("Access-Control-Allow-Origin"), h.get("Access-Control-Allow-Credentials")
    except (OSError, ValueError):
        return None, None


def run(target: str, timeout: float = 8.0, logger=None):
    """Check ``target`` for CORS misconfigurations. Returns findings dict."""
    url = http.base_url(target)
    print(colors.info(f"CORS check for {colors.bold(url)}"))
    if logger:
        logger.event("cors_check", url)

    findings = []

    # 1) Reflected arbitrary origin
    acao, acac = _probe(url, _EVIL, timeout)
    creds = (acac or "").lower() == "true"
    if acao == _EVIL:
        if creds:
            findings.append("Reflects arbitrary Origin WITH credentials (critical)")
        else:
            findings.append("Reflects arbitrary Origin (no credentials)")
    elif acao == "*":
        if creds:
            findings.append("Wildcard ACAO with credentials (invalid + risky)")
        else:
            findings.append("Wildcard ACAO (public API — often intended)")

    # 2) null origin trust
    acao_null, acac_null = _probe(url, "null", timeout)
    if acao_null == "null":
        note = "Trusts 'null' Origin"
        if (acac_null or "").lower() == "true":
            note += " WITH credentials (critical)"
        findings.append(note)

    if not findings:
        print(colors.ok("No obvious CORS misconfiguration detected."))
    else:
        for f in findings:
            crit = "critical" in f
            print((colors.err if crit else colors.warn)(f"  {f}"))

    if logger:
        logger.event("cors_check", url, f"findings={len(findings)}")
    return {"acao": acao, "acac": acac, "findings": findings}
