"""
modules/subdomains.py — Subdomain enumeration via subfinder, amass, assetfinder.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines, merge_files
from core.checks import require_one_of
from core.console import success, warning, skipped, found, info


TOOLS = ["subfinder", "amass", "assetfinder"]


def run_subdomain_enum(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("subdomains")
    available = require_one_of(TOOLS)

    if not available:
        warning("No subdomain tools found — skipping")
        return {}

    # ── resume check ──────────────────────────────────────────────────────────
    if ctx.is_done("subdomains", "all_subdomains.txt"):
        info("subdomains already complete — skipping (resume mode)")
        merged = d / "all_subdomains.txt"
        ctx.all_subdomains = read_lines(merged)
        return {"all_subdomains": str(merged), "count": len(ctx.all_subdomains)}

    partial_files = []

    # ── subfinder ──────────────────────────────────────────────────────────────
    if "subfinder" in available:
        out = d / "subfinder.txt"
        run(
            f"subfinder -d {ctx.domain} -silent -all -o {out} -t {ctx.threads}",
            timeout=600,
        )
        lines = read_lines(out)
        found("subfinder", len(lines), out)
        partial_files.append(out)
    else:
        skipped("subfinder")

    # ── amass ──────────────────────────────────────────────────────────────────
    if "amass" in available:
        out = d / "amass.txt"
        run(
            f"amass enum -passive -d {ctx.domain} -o {out}",
            timeout=900,
        )
        lines = read_lines(out)
        found("amass", len(lines), out)
        partial_files.append(out)
    else:
        skipped("amass")

    # ── assetfinder ────────────────────────────────────────────────────────────
    if "assetfinder" in available:
        out = d / "assetfinder.txt"
        rc, stdout, _ = run(
            f"assetfinder --subs-only {ctx.domain}",
            capture=True,
            timeout=300,
        )
        if rc == 0 and stdout:
            write_lines(out, stdout.splitlines())
            lines = read_lines(out)
            found("assetfinder", len(lines), out)
            partial_files.append(out)
    else:
        skipped("assetfinder")

    # ── merge all ──────────────────────────────────────────────────────────────
    merged = d / "all_subdomains.txt"
    all_subs = merge_files(partial_files, merged)
    found("TOTAL (deduplicated)", len(all_subs), merged)

    # share with context
    ctx.all_subdomains = all_subs

    return {"all_subdomains": str(merged), "count": len(all_subs)}
