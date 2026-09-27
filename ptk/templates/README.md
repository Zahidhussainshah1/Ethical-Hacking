# templscan templates

These JSON files drive the `templscan` engine (a pure-Python, nuclei-style
scanner). Templates here are **detection-only** — they check for exposed files
and misconfigurations, not exploitation.

## Where templates load from

`templscan` and `workflow` load templates from these locations, in order:

1. **Built-in:** this directory (`ptk/templates/`)
2. **Your custom templates:** `~/.ptk/templates/` — drop `.json` files here and
   they load automatically (override with `PTK_TEMPLATES_DIR`)
3. **Extra dir:** anything you pass with `templscan -T /path/to/dir`

## Manage templates from the phone

```bash
python ptk.py templates where             # show the two template dirs
python ptk.py templates list              # list every loaded template
python ptk.py templates new my-check      # scaffold ~/.ptk/templates/my-check.json
python ptk.py templates validate f.json   # check a template is well-formed
```

## Format

```json
{
  "id": "unique-id",
  "info": {"name": "Human name", "severity": "info|low|medium|high|critical"},
  "requests": [
    {
      "method": "GET",
      "path": ["/path-one", "/path-two"],
      "headers": {"Origin": "https://example.com"},
      "matchers-condition": "and",
      "matchers": [
        {"type": "status", "status": [200]},
        {"type": "word",  "part": "body",   "words": ["needle"], "condition": "or"},
        {"type": "regex", "part": "header", "regex": ["Set-Cookie: .*"], "condition": "or"}
      ]
    }
  ]
}
```

**Fields**

- `path` — one or more paths appended to the target; the request stops at the
  first path that matches.
- `headers` *(optional)* — extra request headers (e.g. a custom `Origin`).
- `matchers-condition` — `and` (all matchers must pass) or `or` (any).
- Matcher `type`:
  - `status` — `status` is a list of acceptable HTTP codes.
  - `word` — `words` list; `condition` `and`/`or`.
  - `regex` — `regex` list of Python regular expressions; `condition` `and`/`or`.
- Matcher `part` — where to look: `body`, `header`, or `response` (both).

A template is skipped (with a warning) if it fails validation, so a bad custom
file never breaks a scan.
