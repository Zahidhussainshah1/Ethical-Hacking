"""Manage templscan templates from the CLI (list / where / new / validate).

Lets a mobile user discover, scaffold, and check custom templates without
remembering the JSON schema. Custom templates live in ~/.ptk/templates/ and are
auto-loaded by `templscan` and `workflow`.
"""

import json
import os

from ..core import colors
from . import templscan

_STARTER = {
    "id": "my-custom-check",
    "info": {"name": "My custom check", "severity": "info"},
    "requests": [
        {
            "method": "GET",
            "path": ["/path-to-check", "/another-path"],
            "headers": {},
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "part": "body",
                 "words": ["text that must appear"], "condition": "or"}
            ]
        }
    ]
}


def _list(extra_dir):
    templates = templscan._load_templates(extra_dir)
    print(colors.info(f"{len(templates)} template(s) loaded:"))
    for t in templates:
        info = t.get("info", {})
        sev = info.get("severity", "info")
        print(colors.ok(f"{t.get('id'):<28} [{sev}]  {info.get('name', '')}"))
    return templates


def _where():
    print(colors.info("Template directories (loaded in this order):"))
    print(colors.ok(f"  built-in : {os.path.abspath(templscan._BUILTIN_DIR)}"))
    print(colors.ok(f"  user     : {templscan.USER_DIR}"))
    print(colors.dim("  Drop .json files in the user dir — they load automatically."))


def _new(name):
    os.makedirs(templscan.USER_DIR, exist_ok=True)
    tid = name or "my-custom-check"
    tpl = dict(_STARTER)
    tpl["id"] = tid
    tpl["info"] = {"name": tid.replace("-", " ").title(), "severity": "info"}
    path = os.path.join(templscan.USER_DIR, f"{tid}.json")
    if os.path.exists(path):
        print(colors.err(f"Already exists: {path}"))
        return None
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(tpl, fh, indent=2)
    print(colors.ok(f"Created starter template: {path}"))
    print(colors.dim("  Edit it (nano/vi), then run:  ptk templscan <target>"))
    return path


def _validate(file):
    if not file or not os.path.isfile(file):
        print(colors.err(f"File not found: {file}"))
        return False
    try:
        with open(file, "r", encoding="utf-8") as fh:
            tpl = json.load(fh)
    except ValueError as e:
        print(colors.err(f"Invalid JSON: {e}"))
        return False
    problems = templscan.validate_template(tpl)
    if problems:
        print(colors.err(f"Invalid template ({len(problems)} problem(s)):"))
        for p in problems:
            print(colors.warn(f"  - {p}"))
        return False
    print(colors.ok(f"Valid template: id='{tpl.get('id')}', "
                    f"{len(tpl.get('requests', []))} request(s)"))
    return True


def run(action: str, arg=None, logger=None):
    """Dispatch a templates subcommand: list | where | new | validate."""
    action = (action or "list").lower()
    if logger:
        logger.event("templates", action, str(arg or ""))
    if action == "list":
        _list(arg)
    elif action == "where":
        _where()
    elif action == "new":
        _new(arg)
    elif action == "validate":
        _validate(arg)
    else:
        print(colors.err(f"Unknown action '{action}'. "
                         f"Use: list | where | new <id> | validate <file>"))
