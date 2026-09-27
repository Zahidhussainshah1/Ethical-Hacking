"""Per-target workspace storage.

A workspace is a directory under ~/.ptk/ws/<target>/ that holds the organized
outputs of a recon run (subdomains, live hosts, findings, report). Keeping
results on disk per target lets a mobile user work a program in short bursts
over days and resume where they left off, instead of re-running everything.
"""

import json
import os
import re

_BASE = os.environ.get("PTK_WS_DIR", os.path.join(os.path.expanduser("~"), ".ptk", "ws"))


def _slug(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip().lower()).strip("_")
    return slug or "target"


def base_dir() -> str:
    return _BASE


class Workspace:
    def __init__(self, name: str):
        self.name = name
        self.dir = os.path.join(_BASE, _slug(name))
        os.makedirs(self.dir, exist_ok=True)

    def path(self, filename: str) -> str:
        return os.path.join(self.dir, filename)

    def exists(self, filename: str) -> bool:
        p = self.path(filename)
        return os.path.isfile(p) and os.path.getsize(p) > 0

    def write_lines(self, filename, lines) -> str:
        p = self.path(filename)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(str(x) for x in lines) + ("\n" if lines else ""))
        return p

    def read_lines(self, filename):
        if not self.exists(filename):
            return []
        with open(self.path(filename), "r", encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip()]

    def write_json(self, filename, obj) -> str:
        p = self.path(filename)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, default=str)
        return p

    def write_text(self, filename, text) -> str:
        p = self.path(filename)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p
