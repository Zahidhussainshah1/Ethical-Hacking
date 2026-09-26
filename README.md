# PTK — Pentest Toolkit for Termux

An open-source, Python-based reconnaissance and information-gathering toolkit
built to run on **Termux** (Android) as well as regular Linux/macOS. It bundles
common recon tasks behind a single CLI with an interactive menu, an
authorization gate, and per-session logging.

> ⚠️ **For authorized security testing and education only.**
> Only use PTK against systems you own or have **explicit written permission**
> to test. Unauthorized scanning or access is illegal in most jurisdictions.
> You are solely responsible for how you use this software.

Every tool is **unprivileged** — no root required — so the whole kit runs on a
stock Termux install (or any Linux/macOS shell). Run `python ptk.py list` to see
all commands, or `python ptk.py` for the interactive menu.

## Features

**Network**

| Command    | What it does                                              | Type   |
|------------|-----------------------------------------------------------|--------|
| `discover` | TCP "ping sweep" host discovery across a host/CIDR        | active |
| `scan`     | Multi-threaded TCP connect port scan with service names   | active |
| `banner`   | Reads a service banner from a chosen port                 | active |
| `netinfo`  | Local hostname / local IP / public IP                     | local  |

**DNS**

| Command  | What it does                                                | Type    |
|----------|-------------------------------------------------------------|---------|
| `dns`    | A/AAAA/MX/NS/TXT/CNAME/SOA records (via `dig` or stdlib)     | passive |
| `subs`   | Subdomain enumeration by resolving a wordlist               | passive |
| `rdns`   | Reverse DNS (PTR) over a host or CIDR                       | passive |
| `axfr`   | Zone-transfer (AXFR) misconfiguration check                 | passive |
| `whois`  | Registration data (`whois` binary or IANA socket fallback)  | passive |

**Web**

| Command   | What it does                                               | Type   |
|-----------|------------------------------------------------------------|--------|
| `http`    | Status + security headers, flags missing hardening headers | active |
| `tls`     | TLS/SSL certificate + protocol/cipher inspector, expiry    | active |
| `webtech` | Passive technology fingerprint (CMS/framework/server)      | active |
| `robots`  | Fetches & parses robots.txt and sitemap.xml                | active |
| `cors`    | CORS misconfiguration checks (origin reflection, null)     | active |
| `dirs`    | Content/directory discovery from a wordlist                | active |

**Utilities (offline — no network)**

| Command    | What it does                                              |
|------------|-----------------------------------------------------------|
| `hashid`   | Identify likely hash type by format/length                |
| `hashgen`  | Generate MD5/SHA-1/224/256/384/512 digests of a string    |
| `encode`   | Encode/decode base64, base32, hex, url, rot13             |
| `jwt`      | Decode & inspect a JWT (flags `alg=none`, expiry, HS*)    |
| `wordlist` | Generate a targeted wordlist (case/leet/suffix variants)  |

**Reporting**

| Command  | What it does                                                |
|----------|-------------------------------------------------------------|
| `report` | Export a Markdown report from the session's JSON results    |

### Design principles

- **No pip dependencies** — pure standard library. Optional `dig`/`whois`
  binaries give richer output; the tool falls back gracefully without them.
- **Authorization gate** — modules marked *active* (they touch the target
  directly) require confirmation first, or `PTK_AUTHORIZED=1` for scoped
  scripted runs. *Passive* modules query third-party infrastructure (DNS,
  WHOIS) rather than the target.
- **Audit logging** — every run is recorded under `~/.ptk/logs/` as a text log
  plus a structured JSON file that `report` turns into Markdown.
- **Color output** that auto-disables when piped or when `NO_COLOR` is set.

### Deliberately out of scope

To keep this a defensible, recon/assessment-focused open-source project, PTK
**does not** include: credential brute-forcers against live services, exploit
or payload delivery, phishing kits, command-and-control, or
detection-evasion/anti-forensics tooling. It focuses on discovery,
enumeration, analysis, and reporting — the phases where a mobile toolkit is
most useful and least likely to be misused.

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

List every command, or get help for one:

```bash
python ptk.py list
python ptk.py scan -h
```

Direct subcommands (a few examples):

```bash
python ptk.py discover 10.0.0.0/24             # live-host sweep
python ptk.py scan 192.0.2.10 -p 1-1024 -t 0.5 # custom port range + timeout
python ptk.py banner example.com -p 22
python ptk.py dns example.com
python ptk.py subs example.com -W words.txt
python ptk.py axfr example.com                 # zone-transfer check
python ptk.py http https://example.com
python ptk.py tls example.com -p 443
python ptk.py webtech https://example.com
python ptk.py robots https://example.com
python ptk.py cors https://api.example.com
python ptk.py dirs https://example.com -W paths.txt
python ptk.py whois example.com

# offline utilities
python ptk.py hashid 5f4dcc3b5aa765d61d8327deb882cf99
python ptk.py hashgen "some string"
python ptk.py encode base64 "hello"            # add -d to decode
python ptk.py jwt eyJhbGciOi...
python ptk.py wordlist "acme,admin,2025" -o custom.txt

# turn this session's results into a Markdown report
python ptk.py report
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
ptk.py                     # thin entry point (CLI + interactive menu)
ptk/
  registry.py              # declarative command table -> drives CLI & menu
  core/
    authorization.py       # scope confirmation gate
    banner.py              # ASCII banner + legal notice
    colors.py              # TTY-aware color helpers
    http.py                # shared stdlib HTTP helper
    logger.py              # per-session audit log + JSON results
    utils.py               # target parsing, validation, port specs
  modules/                 # one file per tool (network / dns / web / utility)
    port_scan.py  host_discovery.py  banner_grab.py  netinfo.py
    dns_recon.py  subdomain_enum.py  reverse_dns.py  zone_transfer.py  whois_lookup.py
    http_headers.py  tls_info.py  web_tech.py  robots_sitemap.py  cors_check.py  dir_enum.py
    hashid.py  hashgen.py  encoder.py  jwt_tool.py  wordlist_gen.py
    report.py
install.sh                 # Termux installer
```

Adding a tool is a two-step job: drop a module with a `run(...)` function in
`ptk/modules/`, then add one `Command(...)` entry to `ptk/registry.py`. The
CLI subcommand and the interactive menu entry are generated from it
automatically.

## Roadmap

- More passive OSINT sources (certificate transparency, DNS history)
- HTML report output in addition to Markdown/JSON
- Optional rate limiting / jitter for scans
- Unit tests + CI

## Contributing

Issues and pull requests are welcome. Please keep new modules within the
ethical scope of the project (recon / assessment / defensive tooling — see
"Deliberately out of scope" above) and preserve the authorization gate and
logging conventions.

## License

[MIT](LICENSE) © Zahid Hussain Shah
