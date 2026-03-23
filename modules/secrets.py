"""
modules/secrets.py — Secret scanning via trufflehog and gitleaks.

Findings are written to:
  ~/Desktop/<domain>-RECON/secrets/secrets_found.txt
  ~/Desktop/<domain>-RECON/secrets/trufflehog.json
  ~/Desktop/<domain>-RECON/secrets/gitleaks.json
"""

from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines
from core.checks import require_one_of
from core.console import warning, skipped, found, info, success, error


TOOLS = ["trufflehog", "gitleaks"]


def _get_js_files_and_urls(ctx: RunnerContext) -> tuple[list[str], list[str]]:
    """Get JS/interesting URLs from crawl output."""
    crawl_file = ctx.out_dir / "crawl" / "all_urls.txt"
    if not crawl_file.exists():
        return [], []
    all_urls = read_lines(crawl_file)
    js_urls  = [u for u in all_urls if u.endswith(".js")]
    all_urls = all_urls[:500]  # cap
    return js_urls, all_urls


def run_secrets(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("secrets")
    available = require_one_of(TOOLS)

    if not available:
        warning("No secret scanning tools found — skipping")
        return {}

    all_findings: list[str] = []

    # ── trufflehog ─────────────────────────────────────────────────────────────
    if "trufflehog" in available:
        info("trufflehog: scanning domain via git history + filesystem...")
        out_json = d / "trufflehog.json"

        # Scan GitHub org if reachable
        rc, stdout, _ = run(
            [
                "trufflehog",
                "github",
                "--org", ctx.domain.split(".")[0],
                "--json",
                "--only-verified",
            ],
            capture=True,
            timeout=600,
        )
        if stdout:
            out_json.write_text(stdout)
            lines = [l for l in stdout.splitlines() if l.strip()]
            found("trufflehog (github)", len(lines), out_json)
            all_findings.extend(lines)

        # Also scan the HTTP endpoint directly
        live_file = ctx.out_dir / "http_probe" / "live_hosts.txt"
        if live_file.exists():
            for url in read_lines(live_file)[:10]:
                out_url = d / f"trufflehog_{url.replace('://', '_').replace('/', '_')[:60]}.json"
                rc, stdout, _ = run(
                    ["trufflehog", "http", "--url", url, "--json", "--only-verified"],
                    capture=True,
                    timeout=120,
                )
                if stdout and stdout.strip():
                    out_url.write_text(stdout)
                    lines = [l for l in stdout.splitlines() if l.strip()]
                    all_findings.extend(lines)
                    found(f"trufflehog [{url}]", len(lines), out_url)
    else:
        skipped("trufflehog")

    # ── gitleaks ───────────────────────────────────────────────────────────────
    if "gitleaks" in available:
        info("gitleaks: scanning for secrets in crawled content...")
        js_urls, all_urls = _get_js_files_and_urls(ctx)

        # If we have a local repo path to scan (uncommon in recon but possible)
        # For web recon, point gitleaks at the output directory itself
        out_json = d / "gitleaks.json"
        rc, stdout, stderr = run(
            [
                "gitleaks",
                "detect",
                "--source", str(ctx.out_dir),
                "--report-format", "json",
                "--report-path", str(out_json),
                "--no-git",
                "--exit-code", "0",
            ],
            timeout=300,
        )
        if out_json.exists():
            lines = read_lines(out_json)
            found("gitleaks", len(lines), out_json)
            all_findings.extend(lines)
    else:
        skipped("gitleaks")

    # ── consolidated output ────────────────────────────────────────────────────
    secrets_file = d / "secrets_found.txt"
    if all_findings:
        write_lines(secrets_file, all_findings)
        success(f"[bold red]SECRETS FOUND:[/bold red] {len(all_findings)} potential hits → {secrets_file}")
    else:
        info("No verified secrets found")
        secrets_file.write_text("# No secrets found\n")

    return {"secrets": str(secrets_file), "count": len(all_findings)}
