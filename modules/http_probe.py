"""
modules/http_probe.py — HTTP probing via httpx, WAF detection (wafw00f), tech fingerprinting (whatweb).
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import check_tool
from core.console import success, warning, skipped, found, info


def _build_input(ctx: RunnerContext, d: Path) -> Path:
    """Build the list of hosts to probe."""
    # Prefer DNS-resolved list, fall back to raw subdomain list, fall back to domain
    candidates = [
        ctx.out_dir / "dns" / "all_resolved.txt",
        ctx.out_dir / "subdomains" / "all_subdomains.txt",
    ]
    for c in candidates:
        if c.exists() and read_lines(c):
            return c
    # fallback
    fallback = d / "input.txt"
    write_lines(fallback, [ctx.domain])
    return fallback


def run_http_probe(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("http_probe")
    input_file = _build_input(ctx, d)

    live_urls_file = d / "live_urls.txt"
    live_hosts_file = d / "live_hosts.txt"

    # ── httpx ──────────────────────────────────────────────────────────────────
    if not check_tool("httpx"):
        warning("httpx not found — cannot probe HTTP")
        return {}

    # ── resume check ──────────────────────────────────────────────────────────
    if ctx.is_done("http_probe", "live_hosts.txt"):
        info("http_probe already complete — skipping (resume mode)")
        live_hosts_file = d / "live_hosts.txt"
        ctx.live_urls = read_lines(live_hosts_file)
        return {"live_urls": str(d / "live_urls.txt"), "count": len(ctx.live_urls)}

    run(
        [
            "httpx",
            "-l", str(input_file),
            "-silent",
            "-o", str(live_urls_file),
            "-threads", str(ctx.effective_threads(100)),
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-follow-redirects",
        ],
        timeout=600,
    )
    live_urls = read_lines(live_urls_file)
    found("httpx live URLs", len(live_urls), live_urls_file)

    # extract just the base URL for passing to other modules
    base_urls = []
    for line in live_urls:
        url = line.split(" ")[0].strip()
        if url:
            base_urls.append(url)
    write_lines(live_hosts_file, base_urls)

    ctx.live_urls = base_urls

    # ── wafw00f ────────────────────────────────────────────────────────────────
    if check_tool("wafw00f") and base_urls:
        waf_out = d / "wafw00f.txt"
        info("Running wafw00f against live hosts...")
        results = []
        # wafw00f one at a time (it doesn't take list files)
        for url in base_urls[:50]:  # cap at 50 to avoid excessive runtime
            rc, stdout, _ = run(
                f"wafw00f {url} -a",
                capture=True, timeout=30, silent=True,
            )
            if stdout.strip():
                results.append(f"{url}\n{stdout.strip()}")
        if results:
            waf_out.write_text("\n\n".join(results))
            found("wafw00f results", len(results), waf_out)
    else:
        skipped("wafw00f")

    # ── whatweb ────────────────────────────────────────────────────────────────
    if check_tool("whatweb") and base_urls:
        whatweb_out = d / "whatweb.txt"
        info("Running whatweb tech fingerprinting...")
        # feed list via stdin or use a file
        urls_tmp = d / "urls_tmp.txt"
        write_lines(urls_tmp, base_urls[:100])
        run(
            f"whatweb --input-file={urls_tmp} --log-brief={whatweb_out} -t {min(ctx.threads, 20)}",
            timeout=600,
        )
        lines = read_lines(whatweb_out)
        found("whatweb", len(lines), whatweb_out)
        urls_tmp.unlink(missing_ok=True)
    else:
        skipped("whatweb")

    return {"live_urls": str(live_urls_file), "count": len(base_urls)}
