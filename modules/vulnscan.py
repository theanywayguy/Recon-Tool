"""
modules/vulnscan.py — Template-based vulnerability scanning via nuclei,
with a structured triage report grouped by severity.
"""

import json
from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import check_tool
from core.console import console, warning, skipped, found, info, success

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
    "unknown":  "dim",
}


def _get_targets(ctx: RunnerContext) -> Path | None:
    live_file = ctx.out_dir / "http_probe" / "live_hosts.txt"
    if live_file.exists() and read_lines(live_file):
        return live_file
    fallback = ctx.module_dir("vulnscan") / "targets.txt"
    write_lines(fallback, [f"https://{ctx.domain}", f"http://{ctx.domain}"])
    return fallback


def _parse_jsonl(path: Path) -> list[dict]:
    """Parse nuclei JSONL output into a list of finding dicts."""
    findings = []
    for line in read_lines(path):
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


def _write_triage_report(findings: list[dict], out_path: Path):
    """
    Write a human-readable triage report grouped by severity.
    Format per finding:
        [SEVERITY] template-id — matched-at
          matcher: matcher-name
          info:    name / description
          tags:    tag1,tag2
    """
    grouped: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("info", {}).get("severity", "unknown").lower()
        grouped.setdefault(sev, []).append(f)

    lines = [
        "=" * 72,
        "  NUCLEI TRIAGE REPORT",
        "=" * 72,
        "",
    ]

    total = 0
    for sev in SEVERITY_ORDER:
        bucket = grouped.get(sev, [])
        if not bucket:
            continue
        lines.append(f"── {sev.upper()} ({len(bucket)}) " + "─" * max(0, 60 - len(sev)))
        for f in bucket:
            template_id  = f.get("template-id", "?")
            matched_at   = f.get("matched-at", f.get("host", "?"))
            matcher_name = f.get("matcher-name", "")
            info_block   = f.get("info", {})
            name         = info_block.get("name", "")
            description  = info_block.get("description", "")
            tags         = ", ".join(info_block.get("tags", []))
            curl_cmd     = f.get("curl-command", "")

            lines.append(f"  [{sev.upper()}] {template_id} — {matched_at}")
            if name:
                lines.append(f"    name    : {name}")
            if matcher_name:
                lines.append(f"    matcher : {matcher_name}")
            if description:
                # truncate long descriptions
                desc_short = description[:120] + ("…" if len(description) > 120 else "")
                lines.append(f"    desc    : {desc_short}")
            if tags:
                lines.append(f"    tags    : {tags}")
            if curl_cmd:
                lines.append(f"    curl    : {curl_cmd}")
            lines.append("")
        total += len(bucket)

    lines += [
        "=" * 72,
        f"  TOTAL: {total} findings",
        "=" * 72,
    ]
    out_path.write_text("\n".join(lines))


def run_vulnscan(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("vulnscan")

    # ── resume check ──────────────────────────────────────────────────────────
    if ctx.is_done("vulnscan", "triage_report.txt"):
        info("vulnscan already complete — skipping (resume mode)")
        triage = d / "triage_report.txt"
        return {"triage": str(triage)}

    if not check_tool("nuclei"):
        skipped("nuclei", "not installed")
        return {}

    targets_file = _get_targets(ctx)
    if not targets_file:
        warning("No targets for nuclei")
        return {}

    info("Updating nuclei templates...")
    run("nuclei -update-templates -silent", timeout=120)

    out_jsonl = d / "nuclei_findings.jsonl"
    out_raw   = d / "nuclei_raw.txt"

    threads = ctx.effective_threads(cap=25)
    rate    = "50" if ctx.stealth else "150"

    info(f"Running nuclei — threads={threads}, rate-limit={rate}/s{' [stealth]' if ctx.stealth else ''}")

    run(
        [
            "nuclei",
            "-l",             str(targets_file),
            "-jsonl-export",  str(out_jsonl),
            "-o",             str(out_raw),
            "-c",             str(threads),
            "-rate-limit",    rate,
            "-silent",
            "-severity",      "low,medium,high,critical",
            "-etags",         "dos",
            "-follow-redirects",
        ],
        timeout=3600,
    )

    # ── parse + triage ────────────────────────────────────────────────────────
    findings = _parse_jsonl(out_jsonl) if out_jsonl.exists() else []

    if not findings:
        # fall back to raw text count
        raw_lines = read_lines(out_raw)
        found("nuclei findings (raw)", len(raw_lines), out_raw)
        return {"raw": str(out_raw), "count": len(raw_lines)}

    triage_path = d / "triage_report.txt"
    _write_triage_report(findings, triage_path)

    # console severity summary
    from collections import Counter
    sev_counts = Counter(
        f.get("info", {}).get("severity", "unknown").lower() for f in findings
    )
    found("nuclei findings", len(findings), triage_path)
    for sev in SEVERITY_ORDER:
        n = sev_counts.get(sev, 0)
        if n:
            color = SEVERITY_COLOR[sev]
            console.print(f"    [{color}]{sev:10}[/{color}] {n}")

    return {"triage": str(triage_path), "jsonl": str(out_jsonl), "count": len(findings)}
