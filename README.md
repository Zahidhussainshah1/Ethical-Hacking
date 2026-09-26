# PTK — Pentest Toolkit for Termux

An open-source, Python-based reconnaissance and information-gathering toolkit
built to run on **Termux** (Android) as well as regular Linux/macOS. It bundles
common recon tasks behind a single CLI with an interactive menu, an
authorization gate, and per-session logging.

> ⚠️ **For authorized security testing and education only.**
> Only use PTK against systems you own or have **explicit written permission**
> to test. Unauthorized scanning or access is illegal in most jurisdictions.
> You are solely responsible for how you use this software.

## Features

| Module        | Command  | What it does                                              | Type    |
|---------------|----------|-----------------------------------------------------------|---------|
| Port scan     | `scan`   | Multi-threaded TCP connect scan with service names        | active  |
| DNS recon     | `dns`    | A/AAAA/MX/NS/TXT/CNAME/SOA records (via `dig` or stdlib)   | passive |
| HTTP headers  | `http`   | Status + security headers, flags missing hardening headers| active  |
| Banner grab   | `banner` | Reads a service banner from a chosen port                 | active  |
| Subdomain enum| `subs`   | Resolves a wordlist of subdomains against public DNS      | passive |
| WHOIS         | `whois`  | Registration data (via `whois` binary or IANA fallback)   | passive |

- **No pip dependencies** — pure standard library. Optional `dig`/`whois`
  binaries give richer output and the tool falls back gracefully without them.
- **Authorization gate** — active modules require confirmation before touching
  a target (or `PTK_AUTHORIZED=1` for scoped scripted runs).
- **Session logging** — every run is recorded under `~/.ptk/logs/`.
- **Color output** that auto-disables when piped or when `NO_COLOR` is set.

## Install (Termux)

```bash
pkg install git -y
git clone https://github.com/zahidhussainshah1/ethical-hacking.git
cd ethical-hacking
bash install.sh        # installs python + optional dig/whois, adds a `ptk` launcher
```

On other systems you just need Python 3.7+ (and optionally `dig` and `whois`):

```bash
git clone https://github.com/zahidhussainshah1/ethical-hacking.git
cd ethical-hacking
python3 ptk.py
```

## Usage

Interactive menu:

```bash
python ptk.py
```

Direct subcommands:

```bash
python ptk.py scan example.com                 # common ports
python ptk.py scan 192.0.2.10 -p 1-1024 -t 0.5 # custom range + timeout
python ptk.py dns example.com
python ptk.py http https://example.com
python ptk.py banner example.com -p 22
python ptk.py subs example.com -W words.txt
python ptk.py whois example.com
```

### Non-interactive authorization

For scripted runs against an in-scope lab, skip the prompt with:

```bash
PTK_AUTHORIZED=1 python ptk.py scan 10.0.0.5 -p 1-1000
```

Only set this for targets you are authorized to test — the confirmation is
still written to the session log.

## Project layout

```
ptk.py                     # CLI entry point + interactive menu
ptk/
  core/
    authorization.py       # scope confirmation gate
    banner.py              # ASCII banner + legal notice
    colors.py              # TTY-aware color helpers
    logger.py              # per-session audit log
    utils.py               # target parsing, validation, port specs
  modules/
    port_scan.py
    dns_recon.py
    http_headers.py
    banner_grab.py
    subdomain_enum.py
    whois_lookup.py
install.sh                 # Termux installer
```

## Roadmap

- Output export (JSON / Markdown reports)
- Additional passive OSINT sources
- Optional rate limiting for scans
- Unit tests + CI

## Contributing

Issues and pull requests are welcome. Please keep new modules within the
ethical scope of the project (recon / defensive tooling) and preserve the
authorization gate and logging conventions.

## License

[MIT](LICENSE) © Zahid Hussain Shah
