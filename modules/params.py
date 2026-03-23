"""
modules/params.py — HTTP parameter discovery via arjun.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import check_tool
from core.console import warning, skipped, found, info


def _get_targets(ctx: RunnerContext) -> list[str]:
    """Prefer crawled URLs, fall back to live hosts."""
    crawl_file = ctx.out_dir / "crawl" / "all_urls.txt"
    live_file  = ctx.out_dir / "http_probe" / "live_hosts.txt"

    if crawl_file.exists():
        urls = read_lines(crawl_file)
        # arjun works per-URL; limit to keep runtime reasonable
        urls = [u for u in urls if "?" in u or u.endswith("/")][:100]
        if urls:
            return urls

    if live_file.exists():
        return read_lines(live_file)[:20]

    return [f"https://{ctx.domain}"]


def run_params(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("params")

    if not check_tool("arjun"):
        skipped("arjun", "not installed")
        return {}

    targets = _get_targets(ctx)
    if not targets:
        warning("No targets for arjun")
        return {}

    info(f"arjun scanning {len(targets)} URLs for hidden parameters...")

    # write targets list
    targets_file = d / "targets.txt"
    write_lines(targets_file, targets)

    out_json = d / "arjun_results.json"
    run(
        [
            "arjun",
            "-i", str(targets_file),
            "--rate-limit", "10",
            "-t", str(min(ctx.threads, 10)),
            "-oJ", str(out_json),
        ],
        timeout=1200,
    )

    if out_json.exists():
        found("arjun output", 1, out_json)
        return {"results": str(out_json)}
    else:
        warning("arjun produced no output")
        return {}
