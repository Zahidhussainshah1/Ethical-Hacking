"""One-command recon pipeline for a single target (mobile-friendly).

Chains the recon stages that a bug-bounty hunter runs by hand
(subdomains -> live-host probe -> template scan -> optional content discovery)
and saves organized, resumable output into a per-target workspace, then writes
a Markdown report. Designed so a phone user runs ONE short command instead of
six, and can re-run to resume (finished stages are reused unless --fresh).

Authorization for the target domain (given once via the CLI gate) covers its
subdomains, which share the same registrable domain and program scope.
"""

import datetime

from ..core import colors, utils
from ..core.workspace import Workspace
from . import crtsh, dir_enum, probe, subdomain_enum, templscan


def _stage(title):
    print(colors.bold(colors.cyan(f"\n=== {title} ===")))


def run(target, workers: int = 40, timeout: float = 8.0, fresh: bool = False,
        do_dirs: bool = False, max_hosts: int = 10, logger=None):
    """Run the recon pipeline against ``target``. Returns a summary dict."""
    domain = utils.normalize_host(target)
    ws = Workspace(domain)
    started = datetime.datetime.now()
    print(colors.info(f"Workspace: {colors.bold(ws.dir)}"))
    if logger:
        logger.event("workflow", domain, f"ws={ws.dir}")

    # -- Stage 1: subdomain discovery (passive: DNS wordlist + CT logs) -------
    _stage("1/4  Subdomain discovery")
    if not fresh and ws.exists("subdomains.txt"):
        subs = ws.read_lines("subdomains.txt")
        print(colors.ok(f"Reusing {len(subs)} subdomains from workspace "
                        f"(use --fresh to redo)"))
    else:
        found = {domain}
        for fqdn, _ in subdomain_enum.run(domain, workers=workers, logger=logger):
            found.add(fqdn)
        try:
            for name in crtsh.run(domain, logger=logger):
                found.add(name)
        except Exception as e:  # noqa: BLE001 - CT is best-effort
            print(colors.warn(f"crt.sh skipped: {e}"))
        subs = sorted(found)
        ws.write_lines("subdomains.txt", subs)
    print(colors.info(f"{len(subs)} candidate host(s)"))

    # -- Stage 2: live-host probe --------------------------------------------
    _stage("2/4  Probing live hosts")
    live_results = probe.run(ws.path("subdomains.txt"), timeout=timeout,
                             workers=workers, logger=logger)
    live_urls = [r["url"] for r in live_results]
    ws.write_lines("live.txt", live_urls)
    ws.write_json("live.json", live_results)
    print(colors.info(f"{len(live_urls)} live host(s)"))

    # -- Stage 3: template scan (nuclei-style) -------------------------------
    _stage(f"3/4  Template scan (top {max_hosts} hosts)")
    findings = []
    for url in live_urls[:max_hosts]:
        for f in templscan.run(url, timeout=timeout, logger=logger):
            findings.append(f)
    ws.write_json("findings.json", findings)
    print(colors.info(f"{len(findings)} finding(s)"))

    # -- Stage 4: optional content discovery ---------------------------------
    dir_hits = []
    _stage("4/4  Content discovery" + ("" if do_dirs else " (skipped — use --dirs)"))
    if do_dirs:
        for url in live_urls[:max_hosts]:
            for path, status, length in dir_enum.run(url, timeout=timeout,
                                                      workers=workers, logger=logger):
                dir_hits.append({"url": url, "path": path, "status": status, "len": length})
        ws.write_json("dirs.json", dir_hits)

    # -- Report ---------------------------------------------------------------
    summary = {
        "target": domain,
        "workspace": ws.dir,
        "subdomains": len(subs),
        "live_hosts": len(live_urls),
        "findings": len(findings),
        "dir_hits": len(dir_hits),
        "elapsed_s": round((datetime.datetime.now() - started).total_seconds(), 1),
    }
    report_path = _write_report(ws, domain, subs, live_urls, findings, dir_hits, summary)

    _stage("Done")
    print(colors.ok(f"Subdomains : {summary['subdomains']}"))
    print(colors.ok(f"Live hosts : {summary['live_hosts']}"))
    fcol = colors.red if findings else colors.ok
    print(fcol(f"Findings   : {summary['findings']}"))
    print(colors.info(f"Report     : {report_path}"))
    print(colors.dim(f"All output saved under: {ws.dir}"))
    if logger:
        logger.record("workflow", domain, summary)
    return summary


def _write_report(ws, domain, subs, live_urls, findings, dir_hits, summary):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# PTK Recon Report — {domain}",
        f"_Generated {ts} · workspace `{ws.dir}`_",
        "",
        "## Summary",
        f"- Subdomains discovered: **{summary['subdomains']}**",
        f"- Live hosts: **{summary['live_hosts']}**",
        f"- Template findings: **{summary['findings']}**",
        f"- Content-discovery hits: **{summary['dir_hits']}**",
        f"- Elapsed: {summary['elapsed_s']}s",
        "",
    ]
    if findings:
        lines += ["## Findings", ""]
        for f in sorted(findings, key=lambda x: x.get("severity", "")):
            lines.append(f"- **[{f.get('severity','?')}]** {f.get('name')} — "
                         f"`{f.get('url')}` ({f.get('status')})")
        lines.append("")
    lines += ["## Live hosts", ""]
    lines += [f"- {u}" for u in live_urls] or ["_none_"]
    lines += ["", "## Subdomains", ""]
    lines += [f"- {s}" for s in subs[:200]]
    if len(subs) > 200:
        lines.append(f"- ... {len(subs) - 200} more (see subdomains.txt)")
    lines += ["", "---", "_PTK — BitCops (https://bitcops.net) — authorized testing only._"]
    return ws.write_text("report.md", "\n".join(lines))
