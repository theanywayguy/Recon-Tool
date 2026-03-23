"""
modules/crawl.py — URL harvesting via katana, gau, waybackurls.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines, merge_files
from core.checks import require_one_of, check_tool
from core.console import warning, skipped, found, info


TOOLS = ["katana", "gau", "waybackurls"]


def _get_live_urls(ctx: RunnerContext) -> list[str]:
    f = ctx.out_dir / "http_probe" / "live_hosts.txt"
    if f.exists():
        return read_lines(f)
    return [f"https://{ctx.domain}"]


def run_crawl(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("crawl")
    available = require_one_of(TOOLS)

    if not available:
        warning("No crawl tools found — skipping")
        return {}

    live_urls = _get_live_urls(ctx)
    partial_files = []

    # ── katana ─────────────────────────────────────────────────────────────────
    if "katana" in available and live_urls:
        info(f"katana crawling {len(live_urls)} URLs...")
        urls_file = d / "katana_input.txt"
        write_lines(urls_file, live_urls)
        out = d / "katana.txt"
        run(
            [
                "katana",
                "-list", str(urls_file),
                "-silent",
                "-o", str(out),
                "-c", str(min(ctx.threads, 20)),
                "-depth", "3",
                "-js-crawl",
                "-form-extraction",
            ],
            timeout=900,
        )
        lines = read_lines(out)
        found("katana", len(lines), out)
        partial_files.append(out)
    else:
        skipped("katana")

    # ── gau ────────────────────────────────────────────────────────────────────
    if "gau" in available:
        out = d / "gau.txt"
        run(
            f"gau --threads {min(ctx.threads, 10)} --subs {ctx.domain}",
            capture=False,
            timeout=600,
        )
        # gau writes to stdout by default; capture it
        rc, stdout, _ = run(
            f"gau --threads {min(ctx.threads, 10)} --subs {ctx.domain}",
            capture=True,
            timeout=600,
        )
        if stdout:
            write_lines(out, stdout.splitlines())
            lines = read_lines(out)
            found("gau", len(lines), out)
            partial_files.append(out)
    else:
        skipped("gau")

    # ── waybackurls ────────────────────────────────────────────────────────────
    if "waybackurls" in available:
        out = d / "waybackurls.txt"
        rc, stdout, _ = run(
            f"waybackurls {ctx.domain}",
            capture=True,
            timeout=300,
        )
        if stdout:
            write_lines(out, stdout.splitlines())
            lines = read_lines(out)
            found("waybackurls", len(lines), out)
            partial_files.append(out)
    else:
        skipped("waybackurls")

    # ── merge ──────────────────────────────────────────────────────────────────
    merged = d / "all_urls.txt"
    all_urls = merge_files(partial_files, merged)
    found("TOTAL URLs (deduplicated)", len(all_urls), merged)

    return {"all_urls": str(merged), "count": len(all_urls)}
