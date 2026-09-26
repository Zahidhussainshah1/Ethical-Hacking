"""Lightweight session logger.

Every module writes structured lines to a per-session log file so that a
tester has an audit trail of what was run against which target and when.
"""

import datetime
import os

_LOG_DIR = os.environ.get(
    "PTK_LOG_DIR", os.path.join(os.path.expanduser("~"), ".ptk", "logs")
)


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class SessionLogger:
    def __init__(self, name: str = "session"):
        os.makedirs(_LOG_DIR, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.path = os.path.join(_LOG_DIR, f"{name}-{stamp}.log")
        self.write("SESSION START")

    def write(self, message: str) -> None:
        line = f"[{_timestamp()}] {message}\n"
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            # Never let logging failure crash a scan.
            pass

    def event(self, module: str, target: str, detail: str = "") -> None:
        self.write(f"{module} target={target} {detail}".rstrip())
