"""
modules/cloud.py — Cloud asset enumeration via cloud_enum.
Checks S3 buckets, Azure Blob, GCP Storage for the target domain.
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import check_tool
from core.console import warning, skipped, found, info


def _build_keyword_list(domain: str) -> list[str]:
    """Generate keyword variations from the domain."""
    base = domain.split(".")[0]  # e.g. "example" from "example.com"
    parts = domain.replace(".", "-").replace("_", "-")
    return list({base, parts, domain, domain.replace(".", "")})


def run_cloud(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("cloud")

    if not check_tool("cloud_enum"):
        skipped("cloud_enum", "not installed — pip install cloud-enum")
        return {}

    keywords = _build_keyword_list(ctx.domain)
    info(f"cloud_enum keywords: {keywords}")

    out_txt = d / "cloud_findings.txt"
    all_results = []

    for kw in keywords:
        out_kw = d / f"cloud_{kw}.txt"
        rc, stdout, _ = run(
            ["cloud_enum", "-k", kw, "--disable-azure-sas", "-o", str(out_kw)],
            capture=True,
            timeout=300,
        )
        if out_kw.exists():
            lines = read_lines(out_kw)
            if lines:
                found(f"cloud_enum [{kw}]", len(lines), out_kw)
                all_results.extend(lines)

    # consolidated
    if all_results:
        write_lines(out_txt, all_results)
        found("TOTAL cloud findings", len(all_results), out_txt)
    else:
        info("No public cloud assets found")
        out_txt.write_text("# No cloud assets found\n")

    return {"findings": str(out_txt), "count": len(all_results)}
