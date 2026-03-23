"""
modules/fuzzing.py — Directory/path fuzzing via ffuf and feroxbuster.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import require_one_of
from core.config import resolve_wordlist
from core.console import warning, skipped, found, info


TOOLS = ["ffuf", "feroxbuster"]


def _get_targets(ctx: RunnerContext) -> list[str]:
    f = ctx.out_dir / "http_probe" / "live_hosts.txt"
    if f.exists():
        urls = read_lines(f)
        # Cap to avoid extremely long runs
        if len(urls) > 20:
            info(f"Limiting fuzzing to first 20 live URLs (found {len(urls)})")
            return urls[:20]
        return urls
    return [f"https://{ctx.domain}"]


def run_fuzzing(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("fuzzing")
    available = require_one_of(TOOLS)

    if not available:
        warning("No fuzzing tools found — skipping")
        return {}

    wl = resolve_wordlist("dir_medium")
    if not wl:
        warning("Directory wordlist not found — skipping fuzzing")
        return {}

    targets = _get_targets(ctx)
    if not targets:
        warning("No live URLs to fuzz")
        return {}

    all_findings = []

    for url in targets:
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:80]

        # ── ffuf ───────────────────────────────────────────────────────────────
        if "ffuf" in available:
            out_json = d / f"ffuf_{safe_name}.json"
            out_txt  = d / f"ffuf_{safe_name}.txt"
            run(
                [
                    "ffuf",
                    "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", str(wl),
                    "-t", str(min(ctx.threads, 40)),
                    "-mc", "200,201,204,301,302,307,401,403,405",
                    "-o", str(out_json),
                    "-of", "json",
                    "-s",
                ],
                timeout=600,
            )
            # also produce a plain text summary
            rc, stdout, _ = run(
                [
                    "ffuf",
                    "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", str(wl),
                    "-t", str(min(ctx.threads, 40)),
                    "-mc", "200,201,204,301,302,307,401,403,405",
                    "-s",
                ],
                capture=True,
                timeout=600,
            )
            if stdout:
                write_lines(out_txt, stdout.splitlines())
                lines = read_lines(out_txt)
                found(f"ffuf [{url}]", len(lines), out_txt)
                all_findings.extend(lines)

        # ── feroxbuster ────────────────────────────────────────────────────────
        elif "feroxbuster" in available:
            out = d / f"ferox_{safe_name}.txt"
            run(
                [
                    "feroxbuster",
                    "--url", url,
                    "--wordlist", str(wl),
                    "--threads", str(min(ctx.threads, 50)),
                    "--status-codes", "200,201,204,301,302,307,401,403,405",
                    "--output", str(out),
                    "--silent",
                    "--no-recursion",
                ],
                timeout=600,
            )
            lines = read_lines(out)
            found(f"feroxbuster [{url}]", len(lines), out)
            all_findings.extend(lines)

    # consolidated summary
    summary = d / "all_findings.txt"
    write_lines(summary, all_findings)
    found("TOTAL fuzzing findings", len(all_findings), summary)

    return {"findings": str(summary), "count": len(all_findings)}
