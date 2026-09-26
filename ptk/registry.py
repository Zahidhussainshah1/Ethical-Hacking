"""Declarative command registry.

Each Command describes its arguments once; the CLI parser AND the interactive
menu are both generated from this data, so adding a module means adding one
Command entry — no duplicated wiring.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .core import utils
from .modules import (
    banner_grab, cors_check, crtsh, dir_enum, dns_recon, dork, encoder,
    hashcrack, hashgen, hashid, host_discovery, http_headers, http_methods,
    ip_geo, jwt_tool, netinfo, port_scan, pwcheck, report, reverse_dns,
    robots_sitemap, spider, subdomain_enum, subnet, tls_info, waf_detect,
    wayback, web_tech, whois_lookup, wordlist_gen, zone_transfer,
)


@dataclass
class Arg:
    name: str                       # attribute / dest
    flag: Optional[str] = None      # e.g. "-p/--ports"; None -> positional
    help: str = ""
    type: Callable = str
    default: object = None
    required: bool = False
    prompt: Optional[str] = None    # interactive prompt; None -> not asked


@dataclass
class Command:
    name: str
    category: str
    help: str
    run: Callable
    active: bool = False
    args: List[Arg] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# run() adapters: call a module then record structured results.
# --------------------------------------------------------------------------- #

def _scan(a, log):
    ports = None
    if getattr(a, "ports", None):
        try:
            ports = utils.parse_ports(a.ports)
        except ValueError as e:
            print(f"Bad port spec: {e}")
            return
    res = port_scan.run(a.target, ports=ports, timeout=a.timeout,
                        workers=a.workers, logger=log)
    log.record("scan", a.target, [{"port": p, "service": s} for p, s in res])


def _dns(a, log):
    log.record("dns", a.target, dns_recon.run(a.target, logger=log))


def _http(a, log):
    log.record("http", a.target, http_headers.run(a.target, timeout=a.timeout, logger=log))


def _banner(a, log):
    log.record("banner", a.target,
               {"port": a.port, "banner": banner_grab.run(a.target, port=a.port,
                                                           timeout=a.timeout, logger=log)})


def _subs(a, log):
    res = subdomain_enum.run(a.target, wordlist=a.wordlist, workers=a.workers, logger=log)
    log.record("subs", a.target, [{"fqdn": f, "ip": i} for f, i in res])


def _whois(a, log):
    whois_lookup.run(a.target, logger=log)
    log.record("whois", a.target, "see session log")


def _discover(a, log):
    log.record("discover", a.target,
               host_discovery.run(a.target, timeout=a.timeout, workers=a.workers, logger=log))


def _rdns(a, log):
    res = reverse_dns.run(a.target, workers=a.workers, logger=log)
    log.record("rdns", a.target, [{"ip": i, "name": n} for i, n in res])


def _axfr(a, log):
    log.record("axfr", a.target, zone_transfer.run(a.target, logger=log))


def _tls(a, log):
    log.record("tls", a.target, tls_info.run(a.target, port=a.port, timeout=a.timeout, logger=log))


def _webtech(a, log):
    log.record("webtech", a.target, web_tech.run(a.target, timeout=a.timeout, logger=log))


def _robots(a, log):
    log.record("robots", a.target, robots_sitemap.run(a.target, timeout=a.timeout, logger=log))


def _cors(a, log):
    log.record("cors", a.target, cors_check.run(a.target, timeout=a.timeout, logger=log))


def _dirs(a, log):
    res = dir_enum.run(a.target, wordlist=a.wordlist, timeout=a.timeout,
                       workers=a.workers, logger=log)
    log.record("dirs", a.target, [{"path": p, "status": s, "len": l} for p, s, l in res])


def _hashid(a, log):
    log.record("hashid", a.value[:16], hashid.run(a.value, logger=log))


def _hashgen(a, log):
    log.record("hashgen", "input", hashgen.run(a.text, logger=log))


def _encode(a, log):
    encoder.run(a.scheme, a.text, decode=a.decode, logger=log)


def _jwt(a, log):
    log.record("jwt", "token", jwt_tool.run(a.token, logger=log))


def _wordlist(a, log):
    wordlist_gen.run(a.keywords, outfile=a.out, use_leet=not a.no_leet, logger=log)


def _netinfo(a, log):
    log.record("netinfo", "local", netinfo.run(logger=log))


def _report(a, log):
    report.run(session=a.session, outfile=a.out, logger=log)


def _crtsh(a, log):
    log.record("crtsh", a.target, crtsh.run(a.target, logger=log))


def _wayback(a, log):
    log.record("wayback", a.target, wayback.run(a.target, limit=a.limit, logger=log))


def _ipgeo(a, log):
    log.record("ipgeo", a.target, ip_geo.run(a.target, logger=log))


def _waf(a, log):
    log.record("waf", a.target, waf_detect.run(a.target, timeout=a.timeout, logger=log))


def _methods(a, log):
    log.record("methods", a.target, http_methods.run(a.target, timeout=a.timeout, logger=log))


def _spider(a, log):
    log.record("spider", a.target,
               spider.run(a.target, depth=a.depth, max_pages=a.max_pages,
                          timeout=a.timeout, logger=log))


def _dork(a, log):
    dork.run(a.domain, logger=log)


def _subnet(a, log):
    log.record("subnet", a.cidr, subnet.run(a.cidr, logger=log))


def _hashcrack(a, log):
    hashcrack.run(a.hash, a.wordlist, algo=a.algo, logger=log)


def _pwcheck(a, log):
    pwcheck.run(a.password, logger=log)


# --------------------------------------------------------------------------- #
# Common argument builders
# --------------------------------------------------------------------------- #

def _target(prompt="Target host/IP"):
    return Arg("target", None, "target host, IP, domain, or URL", prompt=prompt)


def _timeout(default):
    return Arg("timeout", "-t/--timeout", "socket timeout (s)", float, default)


def _workers(default):
    return Arg("workers", "-w/--workers", "concurrent workers", int, default)


# --------------------------------------------------------------------------- #
# Command table
# --------------------------------------------------------------------------- #

COMMANDS = [
    # -- Network -----------------------------------------------------------
    Command("discover", "Network", "TCP host discovery (ping sweep)", _discover, active=True,
            args=[_target("Target host or CIDR"), _timeout(0.5), _workers(100)]),
    Command("scan", "Network", "TCP connect port scan", _scan, active=True,
            args=[_target(), Arg("ports", "-p/--ports", "e.g. 22,80,443 or 1-1024",
                                 prompt="Ports (blank=common)"),
                  _timeout(1.0), _workers(100)]),
    Command("banner", "Network", "Grab a service banner from a port", _banner, active=True,
            args=[_target(), Arg("port", "-p/--port", "port", int, required=True, prompt="Port"),
                  _timeout(5.0)]),
    Command("netinfo", "Network", "Show local + public IP info", _netinfo, args=[]),

    # -- DNS ---------------------------------------------------------------
    Command("dns", "DNS", "DNS record recon", _dns,
            args=[_target("Domain")]),
    Command("subs", "DNS", "Subdomain enumeration via DNS", _subs,
            args=[_target("Domain"), Arg("wordlist", "-W/--wordlist", "wordlist path",
                                         prompt="Wordlist (blank=built-in)"),
                  _workers(50)]),
    Command("rdns", "DNS", "Reverse DNS over host/CIDR", _rdns,
            args=[_target("Host or CIDR"), _workers(50)]),
    Command("axfr", "DNS", "Zone transfer (AXFR) check", _axfr,
            args=[_target("Domain")]),
    Command("whois", "DNS", "WHOIS lookup", _whois,
            args=[_target("Domain/IP")]),

    # -- Web ---------------------------------------------------------------
    Command("http", "Web", "HTTP + security header grab", _http, active=True,
            args=[_target("Host or URL"), _timeout(8.0)]),
    Command("tls", "Web", "TLS/SSL certificate inspector", _tls, active=True,
            args=[_target("Host"), Arg("port", "-p/--port", "TLS port", int, 443, prompt="Port"),
                  _timeout(8.0)]),
    Command("webtech", "Web", "Technology fingerprint", _webtech, active=True,
            args=[_target("Host or URL"), _timeout(8.0)]),
    Command("robots", "Web", "robots.txt / sitemap.xml parse", _robots, active=True,
            args=[_target("Host or URL"), _timeout(8.0)]),
    Command("cors", "Web", "CORS misconfiguration check", _cors, active=True,
            args=[_target("Host or URL"), _timeout(8.0)]),
    Command("dirs", "Web", "Content/directory discovery", _dirs, active=True,
            args=[_target("Host or URL"), Arg("wordlist", "-W/--wordlist", "wordlist path",
                                              prompt="Wordlist (blank=built-in)"),
                  _timeout(6.0), _workers(30)]),
    Command("waf", "Web", "WAF detection/fingerprint", _waf, active=True,
            args=[_target("Host or URL"), _timeout(8.0)]),
    Command("methods", "Web", "Allowed HTTP methods (OPTIONS)", _methods, active=True,
            args=[_target("Host or URL"), _timeout(8.0)]),
    Command("spider", "Web", "Shallow same-domain crawler", _spider, active=True,
            args=[_target("Host or URL"),
                  Arg("depth", "-d/--depth", "crawl depth", int, 1, prompt="Depth (blank=1)"),
                  Arg("max_pages", "-m/--max-pages", "max pages", int, 40),
                  _timeout(8.0)]),

    # -- OSINT (passive) ---------------------------------------------------
    Command("crtsh", "OSINT", "Subdomains from Certificate Transparency", _crtsh,
            args=[_target("Domain")]),
    Command("wayback", "OSINT", "Historical URLs from the Wayback Machine", _wayback,
            args=[_target("Domain"),
                  Arg("limit", "-l/--limit", "max URLs", int, 500)]),
    Command("ipgeo", "OSINT", "IP geolocation / ASN lookup", _ipgeo,
            args=[_target("Host or IP")]),
    Command("dork", "OSINT", "Generate search-engine dorks", _dork,
            args=[Arg("domain", None, "domain", prompt="Domain")]),

    # -- Utilities (offline) ----------------------------------------------
    Command("hashid", "Utility", "Identify a hash type", _hashid,
            args=[Arg("value", None, "hash string", prompt="Hash")]),
    Command("hashgen", "Utility", "Generate hashes of a string", _hashgen,
            args=[Arg("text", None, "text to hash", prompt="Text")]),
    Command("encode", "Utility", "Encode/decode (base64/base32/hex/url/rot13)", _encode,
            args=[Arg("scheme", None, "base64|base32|hex|url|rot13", prompt="Scheme"),
                  Arg("text", None, "input text", prompt="Text"),
                  Arg("decode", "-d/--decode", "decode instead of encode", bool, False,
                      prompt="Decode? (y/N)")]),
    Command("jwt", "Utility", "Decode/inspect a JWT", _jwt,
            args=[Arg("token", None, "JWT string", prompt="JWT")]),
    Command("wordlist", "Utility", "Generate a targeted wordlist", _wordlist,
            args=[Arg("keywords", None, "comma/space separated keywords", prompt="Keywords"),
                  Arg("out", "-o/--out", "output file", prompt="Output file (blank=print)"),
                  Arg("no_leet", "--no-leet", "disable leet variants", bool, False)]),
    Command("subnet", "Utility", "Subnet / CIDR calculator", _subnet,
            args=[Arg("cidr", None, "e.g. 10.0.0.0/24", prompt="CIDR")]),
    Command("pwcheck", "Utility", "Password strength analyzer", _pwcheck,
            args=[Arg("password", None, "password to analyze", prompt="Password")]),
    Command("hashcrack", "Utility", "Offline dictionary attack on a hash", _hashcrack,
            args=[Arg("hash", None, "target hash", prompt="Hash"),
                  Arg("wordlist", "-W/--wordlist", "wordlist path", required=True,
                      prompt="Wordlist path"),
                  Arg("algo", "-a/--algo", "force algo (md5/sha1/sha256/...)",
                      prompt="Algo (blank=auto)")]),

    # -- Reporting ---------------------------------------------------------
    Command("report", "Reporting", "Export Markdown report from session results", _report,
            args=[Arg("session", "-s/--session", "results JSON (default: latest)"),
                  Arg("out", "-o/--out", "output .md file")]),
]

BY_NAME = {c.name: c for c in COMMANDS}


def categories():
    """Return ordered dict-like list of (category, [commands])."""
    order = []
    seen = {}
    for c in COMMANDS:
        if c.category not in seen:
            seen[c.category] = []
            order.append(c.category)
        seen[c.category].append(c)
    return [(cat, seen[cat]) for cat in order]
