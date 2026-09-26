"""nuclei-style template scanner (pure Python, JSON templates).

A zero-dependency alternative to Go's nuclei for Termux. Templates are JSON
(not YAML, to avoid a pyyaml dependency) describing HTTP requests and matchers.
The engine sends the requests and evaluates matchers (status / word / regex /
header) with and/or conditions, reporting matched templates by severity.

This is a DETECTION engine — templates check for exposed files and
misconfigurations. It intentionally ships no exploitation templates.

Template format (JSON):
{
  "id": "git-config",
  "info": {"name": "Exposed .git/config", "severity": "medium"},
  "requests": [{
    "method": "GET",
    "path": ["/.git/config"],
    "matchers-condition": "and",
    "matchers": [
      {"type": "status", "status": [200]},
      {"type": "word", "part": "body", "words": ["[core]"], "condition": "or"}
    ]
  }]
}
"""

import glob
import json
import os
import re

from ..core import colors, http

_BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

_SEV_COLOR = {
    "critical": colors.red, "high": colors.red, "medium": colors.yellow,
    "low": colors.cyan, "info": colors.dim,
}


def _load_templates(extra_dir=None):
    templates = []
    dirs = [_BUILTIN_DIR] + ([extra_dir] if extra_dir else [])
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.json"))):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    templates.append(json.load(fh))
            except (OSError, ValueError) as e:
                print(colors.warn(f"Skipping template {os.path.basename(path)}: {e}"))
    return templates


def _match_one(matcher, status, headers, body):
    part = matcher.get("part", "body")
    mtype = matcher.get("type")
    if mtype == "status":
        return status in matcher.get("status", [])
    hay = body if part == "body" else (
        " ".join(f"{k}: {v}" for k, v in headers.items()) if part == "header" else
        body + " " + " ".join(f"{k}: {v}" for k, v in headers.items()))
    if mtype == "word":
        words = matcher.get("words", [])
        cond = matcher.get("condition", "or")
        hits = [w for w in words if w.lower() in hay.lower()]
        return len(hits) == len(words) if cond == "and" else bool(hits)
    if mtype == "regex":
        regs = matcher.get("regex", [])
        cond = matcher.get("condition", "or")
        hits = [r for r in regs if re.search(r, hay, re.IGNORECASE)]
        return len(hits) == len(regs) if cond == "and" else bool(hits)
    return False


def _eval_request(base, req, timeout):
    method = req.get("method", "GET")
    condition = req.get("matchers-condition", "and")
    matchers = req.get("matchers", [])
    for path in req.get("path", ["/"]):
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            resp = http.fetch(url, timeout=timeout, method=method)
        except (OSError, ValueError):
            continue
        status = getattr(resp, "status", getattr(resp, "code", 0))
        headers = {k: v for k, v in resp.headers.items()}
        body = http.read_body(resp, 200_000)
        results = [_match_one(m, status, headers, body) for m in matchers]
        matched = all(results) if condition == "and" else any(results)
        if matched:
            return url, status
    return None


def run(target, templates_dir=None, timeout: float = 8.0, logger=None):
    """Run all templates against ``target``. Returns list of finding dicts."""
    base = http.base_url(target)
    templates = _load_templates(templates_dir)
    print(colors.info(f"Template scan of {colors.bold(base)} — {len(templates)} template(s)"))
    if logger:
        logger.event("templscan", base, f"templates={len(templates)}")

    findings = []
    for tpl in templates:
        info = tpl.get("info", {})
        sev = str(info.get("severity", "info")).lower()
        for req in tpl.get("requests", []):
            hit = _eval_request(base, req, timeout)
            if hit:
                url, status = hit
                color = _SEV_COLOR.get(sev, colors.bold)
                print(color(f"  [{sev}] {info.get('name', tpl.get('id'))} -> {url} ({status})"))
                findings.append({"id": tpl.get("id"), "name": info.get("name"),
                                 "severity": sev, "url": url, "status": status})
                break

    if not findings:
        print(colors.ok("No template matches."))
    else:
        print(colors.info(f"{len(findings)} finding(s)."))
    if logger:
        logger.event("templscan", base, f"findings={len(findings)}")
    return findings
