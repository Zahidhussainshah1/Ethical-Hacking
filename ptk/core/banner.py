"""ASCII banner and legal notice."""

from . import brand, colors
from .. import __version__

BANNER = r"""
  ____  _____ _  __
 |  _ \|_   _| |/ /   Pentest Toolkit for Termux
 | |_) | | | | ' /    Recon & information gathering
 |  __/  | | | . \    v{ver}
 |_|     |_| |_|\_\   Authorized testing only
""".strip("\n")

LEGAL = (
    "This tool is for AUTHORIZED security testing and education only.\n"
    "Only scan systems you own or have explicit written permission to test.\n"
    "Unauthorized access to computer systems is illegal in most jurisdictions.\n"
    "You are solely responsible for your use of this software."
)


def show():
    # Re-assert canonical branding before displaying it.
    brand.verify()
    print(colors.cyan(BANNER.format(ver=__version__)))
    print(colors.bold(colors.magenta(f"  {brand.line()}")))
    print(colors.dim(f"  {brand.TAGLINE}"))
    print()
    print(colors.yellow(LEGAL))
    print()
