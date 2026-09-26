"""Render a Markdown report from a session's structured JSON results."""

import glob
import json
import os

from ..core import colors
from ..core.logger import log_dir


def _latest_results():
    files = sorted(glob.glob(os.path.join(log_dir(), "*.json")), key=os.path.getmtime)
    return files[-1] if files else None


def _render_markdown(results):
    lines = ["# PTK Assessment Report", ""]
    if results:
        lines.append(f"_Generated from {len(results)} recorded action(s)._")
        lines.append("")
    for entry in results:
        lines.append(f"## {entry.get('module', '?')} — {entry.get('target', '?')}")
        lines.append(f"*{entry.get('time', '')}*")
        lines.append("")
        data = entry.get("data")
        lines.append("```json")
        lines.append(json.dumps(data, indent=2, default=str))
        lines.append("```")
        lines.append("")
    lines.append("---")
    lines.append("_Report produced by PTK for authorized testing._")
    return "\n".join(lines)


def run(session=None, outfile=None, logger=None):
    """Build a Markdown report from ``session`` JSON (default: most recent)."""
    path = session or _latest_results()
    if not path or not os.path.exists(path):
        print(colors.err("No session results found to report on."))
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            results = json.load(fh)
    except (OSError, ValueError) as e:
        print(colors.err(f"Could not read results: {e}"))
        return None

    markdown = _render_markdown(results)
    outfile = outfile or os.path.splitext(path)[0] + "-report.md"
    try:
        with open(outfile, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(colors.ok(f"Report written to {outfile}"))
    except OSError as e:
        print(colors.err(f"Write failed: {e}"))
        print(markdown)
        return None

    print(colors.info(f"Summarized {len(results)} action(s) from {os.path.basename(path)}"))
    if logger:
        logger.event("report", path, f"actions={len(results)}")
    return outfile
