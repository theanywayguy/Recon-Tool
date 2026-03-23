"""
modules/portscan.py — Port scanning via nmap with user-selected profile.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import check_tool
from core.console import warning, skipped, found, info


def _get_hosts(ctx: RunnerContext) -> list[str]:
    """Get unique IP/hostname list to scan."""
    candidates = [
        ctx.out_dir / "http_probe" / "live_hosts.txt",
        ctx.out_dir / "dns" / "all_resolved.txt",
        ctx.out_dir / "subdomains" / "all_subdomains.txt",
    ]
    for c in candidates:
        if c.exists():
            hosts = read_lines(c)
            if hosts:
                # strip http:// or https:// and any trailing path
                cleaned = [h.split("://")[-1].split("/")[0] for h in hosts]
                return [h for h in cleaned if h]
    return [ctx.domain]


def run_portscan(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("portscan")

    if not check_tool("nmap"):
        skipped("nmap", "not installed")
        return {}

    hosts = _get_hosts(ctx)
    if not hosts:
        warning("No hosts to scan")
        return {}

    # write target list
    targets_file = d / "targets.txt"
    write_lines(targets_file, hosts)

    info(f"nmap scanning {len(hosts)} hosts with flags: {ctx.nmap_flags}")

    out_xml  = d / "nmap.xml"
    out_gnmap = d / "nmap.gnmap"
    out_txt  = d / "nmap.txt"

    run(
        [
            "nmap",
            *ctx.nmap_flags.split(),
            "-iL", str(targets_file),
            "-oA", str(d / "nmap"),   # produces .xml .gnmap .nmap
        ],
        timeout=3600,
    )

    # rename .nmap to .txt for clarity
    nmap_file = d / "nmap.nmap"
    if nmap_file.exists():
        nmap_file.rename(out_txt)

    if out_txt.exists():
        lines = read_lines(out_txt)
        open_ports = [l for l in lines if "/tcp" in l and "open" in l]
        found("open ports", len(open_ports), out_txt)
        return {"results": str(out_txt), "open_ports": len(open_ports)}

    return {}
