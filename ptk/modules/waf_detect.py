"""Web Application Firewall (WAF) detection from response fingerprints."""

import re

from ..core import colors, http

# label -> regex over the combined header/cookie/body blob
_SIGNATURES = {
    "Cloudflare": re.compile(r"cloudflare|__cf_bm|cf-ray"),
    "AWS WAF / CloudFront": re.compile(r"awselb|x-amz-cf-id|x-amzn"),
    "Akamai": re.compile(r"akamai|akamaighost"),
    "Sucuri": re.compile(r"sucuri|x-sucuri"),
    "Imperva/Incapsula": re.compile(r"incap_ses|visid_incap|imperva"),
    "F5 BIG-IP ASM": re.compile(r"bigipserver|f5|x-waf"),
    "ModSecurity": re.compile(r"mod_security|modsecurity|not acceptable"),
    "Barracuda": re.compile(r"barra_counter|barracuda"),
    "Wordfence": re.compile(r"wordfence"),
    "Fastly": re.compile(r"fastly|x-served-by"),
}

# A benign but "suspicious-looking" query the WAF may block.
_PROBE = "?q=<script>alert(1)</script>&id=1' OR '1'='1"


def run(target: str, timeout: float = 8.0, logger=None):
    """Detect a WAF in front of ``target``. Returns dict with matches."""
    base = http.base_url(target)
    print(colors.info(f"WAF detection for {colors.bold(base)}"))
    if logger:
        logger.event("waf_detect", base)

    matched = []
    try:
        resp = http.fetch(base, timeout=timeout)
        blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items()).lower()
        blob += " " + http.read_body(resp, 50_000).lower()
        for label, pat in _SIGNATURES.items():
            if pat.search(blob):
                matched.append(label)
    except (OSError, ValueError) as e:
        print(colors.err(f"Request failed: {e}"))
        return {}

    # Behavioural probe: does a malicious-looking request get blocked?
    blocked = False
    try:
        r2 = http.fetch(base + _PROBE, timeout=timeout)
        code = getattr(r2, "status", getattr(r2, "code", 0))
        if code in (403, 406, 501, 999):
            blocked = True
    except (OSError, ValueError):
        pass

    if matched:
        for m in matched:
            print(colors.ok(f"WAF detected: {m}"))
    if blocked:
        print(colors.warn("Malicious-looking request was blocked (WAF likely present)"))
    if not matched and not blocked:
        print(colors.info("No WAF signature detected (does not prove none exists)."))

    result = {"waf": matched, "probe_blocked": blocked}
    if logger:
        logger.event("waf_detect", base, f"waf={matched} blocked={blocked}")
    return result
