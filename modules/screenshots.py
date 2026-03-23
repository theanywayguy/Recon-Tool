"""
modules/screenshots.py — Visual screenshots via gowitness, with a correlated
triage report that links each screenshot to its HTTP status code, title,
and any nuclei findings for that host.
"""

from pathlib import Path
import json
import re

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import check_tool
from core.console import console, warning, skipped, found, info


# Status codes worth flagging during triage
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500, 502, 503}
PRIORITY_CODES    = {200, 401, 403, 500, 502, 503}


def _get_targets(ctx: RunnerContext) -> list[str]:
    live_file = ctx.out_dir / "http_probe" / "live_hosts.txt"
    if live_file.exists():
        return read_lines(live_file)
    return [f"https://{ctx.domain}"]


def _load_httpx_data(ctx: RunnerContext) -> dict[str, dict]:
    """
    Parse httpx output to build a map of url → {status, title, tech}.
    httpx -o writes lines like:
        https://example.com [200] [Title] [tech1,tech2]
    """
    httpx_file = ctx.out_dir / "http_probe" / "live_urls.txt"
    data: dict[str, dict] = {}
    if not httpx_file.exists():
        return data

    status_re = re.compile(r'\[(\d{3})\]')
    title_re  = re.compile(r'\[(\d{3})\]\s+\[([^\]]*)\]')

    for line in read_lines(httpx_file):
        parts = line.split(" ", 1)
        url   = parts[0].strip()
        rest  = parts[1] if len(parts) > 1 else ""

        status_m = status_re.search(rest)
        title_m  = title_re.search(rest)

        status = int(status_m.group(1)) if status_m else 0
        title  = title_m.group(2).strip() if title_m else ""

        # grab bracketed fields beyond status+title
        brackets = re.findall(r'\[([^\]]+)\]', rest)
        tech = ", ".join(brackets[2:]) if len(brackets) > 2 else ""

        data[url] = {"status": status, "title": title, "tech": tech}
    return data


def _load_nuclei_findings(ctx: RunnerContext) -> dict[str, list[str]]:
    """
    Map host → [finding strings] from nuclei JSONL output.
    """
    jsonl = ctx.out_dir / "vulnscan" / "nuclei_findings.jsonl"
    host_map: dict[str, list[str]] = {}
    if not jsonl.exists():
        return host_map
    for line in read_lines(jsonl):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host  = obj.get("host", obj.get("matched-at", ""))
        sev   = obj.get("info", {}).get("severity", "?").upper()
        tid   = obj.get("template-id", "?")
        host_map.setdefault(host, []).append(f"[{sev}] {tid}")
    return host_map


def _write_correlation_report(
    targets: list[str],
    httpx_data: dict[str, dict],
    nuclei_map: dict[str, list[str]],
    screenshots_dir: Path,
    out_path: Path,
):
    """
    Write triage_report.txt — sorted by priority status codes first,
    each entry showing status, title, tech stack, nuclei hits,
    and the screenshot filename.
    """
    entries = []
    for url in targets:
        meta     = httpx_data.get(url, {})
        status   = meta.get("status", 0)
        title    = meta.get("title", "")
        tech     = meta.get("tech", "")
        findings = nuclei_map.get(url, [])

        # derive expected screenshot filename (gowitness uses URL-safe encoding)
        safe     = re.sub(r'[^\w.-]', '_', url)[:120]
        shot_candidates = list(screenshots_dir.glob(f"{safe}*"))
        shot_name = shot_candidates[0].name if shot_candidates else "not found"

        entries.append({
            "url": url, "status": status, "title": title,
            "tech": tech, "findings": findings, "shot": shot_name,
        })

    # sort: priority codes first, then by status code
    def sort_key(e):
        return (0 if e["status"] in PRIORITY_CODES else 1, e["status"], e["url"])

    entries.sort(key=sort_key)

    lines = [
        "=" * 72,
        "  SCREENSHOT TRIAGE REPORT",
        "  sorted: priority status codes first (200/401/403/5xx), then by code",
        "=" * 72,
        "",
    ]

    for e in entries:
        status  = e["status"]
        color   = "●" if status in PRIORITY_CODES else "○"
        lines.append(f"{color} [{status}]  {e['url']}")
        if e["title"]:
            lines.append(f"    title      : {e['title']}")
        if e["tech"]:
            lines.append(f"    tech       : {e['tech']}")
        if e["findings"]:
            lines.append(f"    nuclei     : {', '.join(e['findings'])}")
        lines.append(f"    screenshot : {e['shot']}")
        lines.append("")

    lines += [
        "=" * 72,
        f"  TOTAL: {len(entries)} hosts",
        f"  With nuclei findings: {sum(1 for e in entries if e['findings'])}",
        "=" * 72,
    ]
    out_path.write_text("\n".join(lines))


def run_screenshots(ctx: RunnerContext) -> dict:
    screenshots_dir = ctx.out_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    # ── resume check ──────────────────────────────────────────────────────────
    if ctx.is_done("screenshots", "triage_report.txt"):
        info("screenshots already complete — skipping (resume mode)")
        return {"triage": str(screenshots_dir / "triage_report.txt")}

    if not check_tool("gowitness"):
        skipped("gowitness", "not installed")
        return {}

    targets = _get_targets(ctx)
    if not targets:
        warning("No live URLs for screenshots")
        return {}

    info(f"Screenshotting {len(targets)} URLs with gowitness...")

    url_list = screenshots_dir / "urls.txt"
    write_lines(url_list, targets)

    threads = ctx.effective_threads(cap=10)

    run(
        [
            "gowitness",
            "file",
            "-f",                  str(url_list),
            "--screenshot-path",   str(screenshots_dir),
            "--threads",           str(threads),
        ],
        timeout=1800,
    )

    shots = list(screenshots_dir.glob("*.png")) + list(screenshots_dir.glob("*.jpg"))
    found("screenshots captured", len(shots), screenshots_dir)

    # ── generate gowitness HTML report ────────────────────────────────────────
    html_report = screenshots_dir / "gowitness_report.html"
    run(
        f"gowitness report generate --screenshot-path {screenshots_dir} --output {html_report}",
        timeout=60,
    )
    if html_report.exists():
        info(f"gowitness HTML report: {html_report}")

    # ── build correlation triage report ───────────────────────────────────────
    info("Building finding-correlated triage report...")
    httpx_data  = _load_httpx_data(ctx)
    nuclei_map  = _load_nuclei_findings(ctx)
    triage_path = screenshots_dir / "triage_report.txt"
    _write_correlation_report(targets, httpx_data, nuclei_map, screenshots_dir, triage_path)
    found("triage report", len(targets), triage_path)

    # surface how many hosts have nuclei hits
    hosts_with_hits = sum(1 for u in targets if nuclei_map.get(u))
    if hosts_with_hits:
        console.print(
            f"  [bold yellow]⚑[/bold yellow]  {hosts_with_hits} screenshotted host(s) have nuclei findings — see triage_report.txt"
        )

    return {
        "screenshots_dir": str(screenshots_dir),
        "count":           len(shots),
        "triage":          str(triage_path),
    }
