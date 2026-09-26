"""Authorization / scope confirmation gate.

Before any active module runs against a target, the tester must confirm they
are authorized to test it. Confirmation can be given interactively, or
non-interactively via the PTK_AUTHORIZED=1 environment variable (useful for
scripted runs on scoped lab targets). Every confirmation is logged.
"""

import os

from . import colors

_confirmed_targets = set()


def is_authorized(target: str, logger=None) -> bool:
    """Return True if the tester has confirmed authorization for ``target``.

    Confirmation is cached per-target for the life of the process so the tester
    is not prompted repeatedly for the same host.
    """
    if target in _confirmed_targets:
        return True

    if os.environ.get("PTK_AUTHORIZED") == "1":
        _confirmed_targets.add(target)
        if logger:
            logger.write(f"AUTHORIZATION target={target} source=env")
        return True

    print(colors.warn(f"You are about to run an active test against: {colors.bold(target)}"))
    print(colors.yellow("    Confirm you have explicit permission to test this target."))
    try:
        answer = input(colors.cyan("    Type 'yes' to continue: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        answer = ""

    authorized = answer in ("yes", "y")
    if authorized:
        _confirmed_targets.add(target)
        if logger:
            logger.write(f"AUTHORIZATION target={target} source=interactive")
    else:
        print(colors.err("Authorization not given. Skipping target."))
        if logger:
            logger.write(f"AUTHORIZATION_DENIED target={target}")
    return authorized
