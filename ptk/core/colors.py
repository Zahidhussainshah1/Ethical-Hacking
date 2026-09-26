"""Terminal color helpers with a no-color fallback.

Colors auto-disable when output is not a TTY or when NO_COLOR is set, so piped
output and logs stay clean.
"""

import os
import sys

_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"


def _wrap(code: str, text: str) -> str:
    if not _ENABLED:
        return text
    return f"{code}{text}{C.RESET}"


def bold(t):    return _wrap(C.BOLD, t)
def dim(t):     return _wrap(C.DIM, t)
def red(t):     return _wrap(C.RED, t)
def green(t):   return _wrap(C.GREEN, t)
def yellow(t):  return _wrap(C.YELLOW, t)
def blue(t):    return _wrap(C.BLUE, t)
def cyan(t):    return _wrap(C.CYAN, t)
def magenta(t): return _wrap(C.MAGENTA, t)


def ok(msg):    return f"{green('[+]')} {msg}"
def info(msg):  return f"{cyan('[*]')} {msg}"
def warn(msg):  return f"{yellow('[!]')} {msg}"
def err(msg):   return f"{red('[-]')} {msg}"
