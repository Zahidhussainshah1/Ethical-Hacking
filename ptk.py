#!/usr/bin/env python3
"""PTK - Pentest Toolkit for Termux.

A modular reconnaissance / red-team recon toolkit that runs unprivileged
(no root) so it works cleanly on Termux and other mobile shells. Provides both
a command-line interface and an interactive menu, generated from a single
command registry. Active modules are gated behind an authorization prompt and
every action is logged for an audit trail.

    python ptk.py                 # interactive menu
    python ptk.py <command> ...   # direct subcommand
    python ptk.py list            # list all commands
    python ptk.py <command> -h    # help for one command
"""

import argparse
import sys
from types import SimpleNamespace

from ptk.core import authorization, banner, colors, utils
from ptk.core.logger import SessionLogger
from ptk.registry import BY_NAME, COMMANDS, categories


def _split_flag(flag):
    """'-p/--ports' -> ('-p', '--ports'); '--no-leet' -> ('--no-leet',)."""
    return tuple(flag.split("/"))


def build_parser():
    p = argparse.ArgumentParser(
        prog="ptk",
        description="PTK - recon toolkit for AUTHORIZED testing only.",
    )
    sub = p.add_subparsers(dest="command")
    sub.add_parser("list", help="list all available commands")

    for cmd in COMMANDS:
        sp = sub.add_parser(cmd.name, help=cmd.help)
        for arg in cmd.args:
            if arg.flag is None:
                sp.add_argument(arg.name, help=arg.help)
            elif arg.type is bool:
                sp.add_argument(*_split_flag(arg.flag), dest=arg.name,
                                action="store_true", help=arg.help)
            else:
                sp.add_argument(*_split_flag(arg.flag), dest=arg.name, type=arg.type,
                                default=arg.default, required=arg.required, help=arg.help)
    return p


def _gate(cmd, ns, logger):
    """Authorization check for active modules that have a target."""
    if cmd.active and getattr(ns, "target", None):
        return authorization.is_authorized(utils.normalize_host(ns.target), logger)
    return True


def run_command(cmd, ns, logger):
    if not _gate(cmd, ns, logger):
        return 1
    cmd.run(ns, logger)
    return 0


def print_list():
    for cat, cmds in categories():
        print(colors.bold(f"\n{cat}"))
        for c in cmds:
            tag = colors.red(" [active]") if c.active else ""
            print(f"  {colors.cyan(c.name):<22} {c.help}{tag}")
    print()


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #

def _ask(prompt):
    try:
        return input(colors.cyan(prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _collect_interactive(cmd):
    """Prompt for a command's arguments; return a namespace or None to cancel."""
    values = {}
    for arg in cmd.args:
        if arg.prompt is None:
            values[arg.name] = arg.default
            continue
        raw = _ask(f"  {arg.prompt}: ")
        if raw is None:
            return None
        if raw == "":
            if arg.flag is None or arg.required:
                print(colors.err(f"  {arg.name} is required."))
                return None
            values[arg.name] = arg.default
            continue
        if arg.type is bool:
            values[arg.name] = raw.lower() in ("y", "yes", "true", "1")
        else:
            try:
                values[arg.name] = arg.type(raw)
            except ValueError:
                print(colors.err(f"  Invalid value for {arg.name}."))
                return None
    return SimpleNamespace(**values)


def _menu_map():
    """Number every command for the interactive menu."""
    mapping = {}
    n = 1
    lines = []
    for cat, cmds in categories():
        lines.append(colors.bold(f"\n {cat}"))
        row = []
        for c in cmds:
            mapping[str(n)] = c
            row.append(f"{colors.cyan(str(n)):>4}  {c.name:<12}")
            if len(row) == 2:
                lines.append("   " + "".join(row))
                row = []
            n += 1
        if row:
            lines.append("   " + "".join(row))
    lines.append(f"\n{colors.cyan('0'):>4}  exit")
    return mapping, "\n".join(lines)


def interactive(logger):
    mapping, menu = _menu_map()
    while True:
        print(menu)
        choice = _ask("\nptk> ")
        if choice is None or choice in ("0", "q", "quit", "exit", ""):
            print(colors.info("Goodbye."))
            return
        cmd = mapping.get(choice) or BY_NAME.get(choice)
        if not cmd:
            print(colors.warn("Unknown option."))
            continue
        print(colors.info(cmd.help))
        ns = _collect_interactive(cmd)
        if ns is None:
            continue
        if (cmd.validate_target and getattr(ns, "target", None)
                and not utils.is_valid_host(utils.normalize_host(ns.target))):
            print(colors.err(f"Invalid target: {ns.target}"))
            continue
        try:
            run_command(cmd, ns, logger)
        except KeyboardInterrupt:
            print(colors.warn("\nInterrupted."))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    banner.show()
    logger = SessionLogger()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        interactive(logger)
        return 0
    if args.command == "list":
        print_list()
        return 0

    cmd = BY_NAME[args.command]
    if (cmd.validate_target and getattr(args, "target", None)
            and not utils.is_valid_host(utils.normalize_host(args.target))):
        print(colors.err(f"Invalid target: {args.target}"))
        return 2

    rc = run_command(cmd, args, logger)
    print(colors.dim(f"\nSession log: {logger.path}"))
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(colors.warn("\nInterrupted."))
        sys.exit(130)
