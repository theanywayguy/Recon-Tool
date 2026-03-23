"""
modules/dns.py — DNS resolution (dnsx), brute-force, massdns, zone transfer.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines, merge_files
from core.checks import check_tool
from core.config import resolve_wordlist
from core.console import success, warning, skipped, found, info, error


def _zone_transfer(ctx: RunnerContext, d: Path):
    """Attempt AXFR zone transfer against all NS records."""
    info("Attempting zone transfer (AXFR)...")
    rc, stdout, _ = run(
        f"dig NS {ctx.domain} +short",
        capture=True, silent=True,
    )
    nameservers = [l.rstrip(".") for l in stdout.splitlines() if l.strip()]

    if not nameservers:
        warning("No NS records found for zone transfer attempt")
        return

    axfr_out = d / "zone_transfer.txt"
    results = []
    for ns in nameservers:
        info(f"Trying AXFR against {ns}")
        rc, stdout, _ = run(
            f"dig AXFR {ctx.domain} @{ns}",
            capture=True, timeout=30,
        )
        if "XFR size" in stdout:
            results.append(f"=== {ns} ===\n{stdout}")

    if results:
        axfr_out.write_text("\n".join(results))
        found("zone transfer", len(results), axfr_out)
    else:
        info("Zone transfer not allowed (expected)")


def run_dns(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("dns")

    # ── Input: subdomains from previous module or build from domain ────────────
    input_file = ctx.out_dir / "subdomains" / "all_subdomains.txt"
    if not input_file.exists() or not read_lines(input_file):
        input_file = d / "input.txt"
        write_lines(input_file, [ctx.domain])
        warning("No subdomain list found — resolving domain only")

    # ── resume check ──────────────────────────────────────────────────────────
    if ctx.is_done("dns", "all_resolved.txt"):
        info("dns already complete — skipping (resume mode)")
        all_resolved_file = d / "all_resolved.txt"
        ctx.resolved_subdomains = read_lines(all_resolved_file)
        return {"resolved": str(all_resolved_file), "count": len(ctx.resolved_subdomains)}

    # ── dnsx: resolve subdomains ───────────────────────────────────────────────
    resolved_file = d / "resolved.txt"
    if check_tool("dnsx"):
        run(
            f"dnsx -l {input_file} -silent -o {resolved_file} -t {ctx.effective_threads(100)}",
            timeout=600,
        )
        resolved = read_lines(resolved_file)
        found("dnsx resolved", len(resolved), resolved_file)
    else:
        skipped("dnsx", "not installed — skipping resolution")
        resolved = []

    # ── dnsx: brute-force subdomains ───────────────────────────────────────────
    brute_file = d / "bruteforce.txt"
    wl = resolve_wordlist("dns_brute")
    if wl and check_tool("dnsx"):
        info(f"DNS brute-force with wordlist: {wl.name}")
        run(
            f"dnsx -d {ctx.domain} -w {wl} -silent -o {brute_file} -t {ctx.effective_threads(100)}",
            timeout=900,
        )
        brute = read_lines(brute_file)
        found("dnsx brute-force", len(brute), brute_file)
    elif not wl:
        warning("DNS wordlist not found — skipping brute-force")
        brute = []
    else:
        brute = []

    # ── massdns: large-scale resolution ───────────────────────────────────────
    massdns_file = d / "massdns.txt"
    resolvers_file = Path(__file__).parent.parent / "data" / "resolvers.txt"
    if check_tool("massdns") and input_file.exists():
        if resolvers_file.exists():
            run(
                f"massdns -r {resolvers_file} -t A -o S -w {massdns_file} {input_file}",
                timeout=600,
            )
            massdns = read_lines(massdns_file)
            found("massdns", len(massdns), massdns_file)
        else:
            warning(f"massdns resolvers file not found at {resolvers_file} — skipping massdns")
    else:
        skipped("massdns")

    # ── merge all resolved ─────────────────────────────────────────────────────
    sources = [f for f in [resolved_file, brute_file, massdns_file] if f.exists()]
    all_resolved_file = d / "all_resolved.txt"
    all_resolved = merge_files(sources, all_resolved_file)
    found("TOTAL resolved (deduplicated)", len(all_resolved), all_resolved_file)

    ctx.resolved_subdomains = all_resolved

    # ── Zone transfer ──────────────────────────────────────────────────────────
    if check_tool("dig"):
        _zone_transfer(ctx, d)
    else:
        skipped("dig", "dnsutils not installed")

    return {"resolved": str(all_resolved_file), "count": len(all_resolved)}
