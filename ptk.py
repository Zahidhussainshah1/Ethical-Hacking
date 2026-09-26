#!/usr/bin/env python3
"""PTK - Pentest Toolkit for Termux.

Entry point providing both a command-line interface (subcommands) and an
interactive menu. Active modules are gated behind an authorization prompt.

    python ptk.py                     # interactive menu
    python ptk.py scan example.com    # subcommand mode
    python ptk.py scan example.com -p 1-1024
    python ptk.py dns example.com
    python ptk.py http example.com
    python ptk.py banner example.com -p 22
    python ptk.py subs example.com
    python ptk.py whois example.com
"""

import argparse
import sys

from ptk.core import authorization, banner, colors, utils
from ptk.core.logger import SessionLogger
from ptk.modules import (
    banner_grab,
    dns_recon,
    http_headers,
    port_scan,
    subdomain_enum,
    whois_lookup,
)

# Modules that actively touch the target require an authorization check.
# Purely passive lookups (DNS, WHOIS, subdomain resolution) query third-party
# infrastructure, not the target, so they run without the gate.
_ACTIVE = {"scan", "http", "banner"}


def _require_target(target: str) -> bool:
    if not utils.is_valid_host(utils.normalize_host(target)):
        print(colors.err(f"Invalid target: {target}"))
        return False
    return True


def _gate(command: str, target: str, logger) -> bool:
    if command in _ACTIVE:
        return authorization.is_authorized(utils.normalize_host(target), logger)
    return True


def cmd_scan(args, logger):
    ports = None
    if args.ports:
        try:
            ports = utils.parse_ports(args.ports)
        except ValueError as e:
            print(colors.err(f"Bad port spec: {e}"))
            return
    port_scan.run(args.target, ports=ports, timeout=args.timeout,
                  workers=args.workers, logger=logger)


def cmd_dns(args, logger):
    dns_recon.run(args.target, logger=logger)


def cmd_http(args, logger):
    http_headers.run(args.target, timeout=args.timeout, logger=logger)


def cmd_banner(args, logger):
    banner_grab.run(args.target, port=args.port, timeout=args.timeout, logger=logger)


def cmd_subs(args, logger):
    subdomain_enum.run(args.target, wordlist=args.wordlist,
                       workers=args.workers, logger=logger)


def cmd_whois(args, logger):
    whois_lookup.run(args.target, logger=logger)


_DISPATCH = {
    "scan": cmd_scan,
    "dns": cmd_dns,
    "http": cmd_http,
    "banner": cmd_banner,
    "subs": cmd_subs,
    "whois": cmd_whois,
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="ptk",
        description="PTK - reconnaissance toolkit for AUTHORIZED testing only.",
    )
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="TCP connect port scan")
    sp.add_argument("target")
    sp.add_argument("-p", "--ports", help="e.g. 22,80,443 or 1-1024 (default: common ports)")
    sp.add_argument("-t", "--timeout", type=float, default=1.0)
    sp.add_argument("-w", "--workers", type=int, default=100)

    dp = sub.add_parser("dns", help="DNS record recon")
    dp.add_argument("target")

    hp = sub.add_parser("http", help="HTTP header / security-header grab")
    hp.add_argument("target")
    hp.add_argument("-t", "--timeout", type=float, default=8.0)

    bp = sub.add_parser("banner", help="Grab a service banner from a port")
    bp.add_argument("target")
    bp.add_argument("-p", "--port", type=int, required=True)
    bp.add_argument("-t", "--timeout", type=float, default=5.0)

    ep = sub.add_parser("subs", help="Subdomain enumeration via DNS")
    ep.add_argument("target")
    ep.add_argument("-W", "--wordlist", help="path to a subdomain wordlist")
    ep.add_argument("-w", "--workers", type=int, default=50)

    wp = sub.add_parser("whois", help="WHOIS lookup")
    wp.add_argument("target")

    return p


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #

_MENU = """
  {n1}  Port scan          {n5}  Subdomain enum
  {n2}  DNS recon          {n6}  WHOIS lookup
  {n3}  HTTP headers       {n0}  Exit
  {n4}  Banner grab
""".format(
    n1=colors.cyan("1"), n2=colors.cyan("2"), n3=colors.cyan("3"),
    n4=colors.cyan("4"), n5=colors.cyan("5"), n6=colors.cyan("6"),
    n0=colors.cyan("0"),
)


def _ask(prompt):
    try:
        return input(colors.cyan(prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def interactive(logger):
    while True:
        print(_MENU)
        choice = _ask("ptk> ")
        if choice in ("0", "q", "quit", "exit", ""):
            print(colors.info("Goodbye."))
            return

        if choice == "1":
            target = _ask("Target host/IP: ")
            if not target or not _require_target(target):
                continue
            if not authorization.is_authorized(utils.normalize_host(target), logger):
                continue
            spec = _ask("Ports (blank = common): ")
            ports = None
            if spec:
                try:
                    ports = utils.parse_ports(spec)
                except ValueError as e:
                    print(colors.err(f"Bad port spec: {e}"))
                    continue
            port_scan.run(target, ports=ports, logger=logger)

        elif choice == "2":
            target = _ask("Domain: ")
            if target and _require_target(target):
                dns_recon.run(target, logger=logger)

        elif choice == "3":
            target = _ask("Target (host or URL): ")
            if not target or not _require_target(target):
                continue
            if authorization.is_authorized(utils.normalize_host(target), logger):
                http_headers.run(target, logger=logger)

        elif choice == "4":
            target = _ask("Target host/IP: ")
            if not target or not _require_target(target):
                continue
            port_s = _ask("Port: ")
            try:
                port = int(port_s)
            except ValueError:
                print(colors.err("Port must be a number."))
                continue
            if authorization.is_authorized(utils.normalize_host(target), logger):
                banner_grab.run(target, port=port, logger=logger)

        elif choice == "5":
            target = _ask("Domain: ")
            if target and _require_target(target):
                wl = _ask("Wordlist path (blank = built-in): ") or None
                subdomain_enum.run(target, wordlist=wl, logger=logger)

        elif choice == "6":
            target = _ask("Domain/IP: ")
            if target and _require_target(target):
                whois_lookup.run(target, logger=logger)

        else:
            print(colors.warn("Unknown option."))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    banner.show()
    logger = SessionLogger()

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        interactive(logger)
        return 0

    if not _require_target(args.target):
        return 2
    if not _gate(args.command, args.target, logger):
        return 1

    _DISPATCH[args.command](args, logger)
    print(colors.dim(f"\nSession log: {logger.path}"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(colors.warn("\nInterrupted."))
        sys.exit(130)
