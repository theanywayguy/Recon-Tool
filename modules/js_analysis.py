"""
modules/js_analysis.py — JavaScript analysis via linkfinder and secretfinder.

Extracts:
  - Hidden endpoints and API paths from JS files (linkfinder)
  - Secrets, tokens, API keys embedded in JS (secretfinder)

Output:
  js_analysis/
  ├── js_urls.txt           — all JS file URLs found in crawl output
  ├── linkfinder_<n>.txt    — endpoints per JS file
  ├── secretfinder_<n>.txt  — secrets per JS file
  ├── all_endpoints.txt     — merged deduplicated endpoints
  └── all_secrets.txt       — merged deduplicated secrets (also copied to secrets/)
"""

import shutil
from pathlib import Path

from core.runner import RunnerContext, run, read_lines, write_lines, merge_files
from core.checks import check_tool
from core.console import console, warning, skipped, found, info, success


def _find_tool_path(name: str) -> str | None:
    """
    linkfinder / secretfinder are often installed as scripts rather than
    binaries. Check PATH first, then common clone locations.
    """
    import shutil as sh
    hit = sh.which(name)
    if hit:
        return hit
    candidates = [
        Path.home() / "tools" / name / f"{name}.py",
        Path.home() / "tools" / name.capitalize() / f"{name}.py",
        Path("/opt") / name / f"{name}.py",
        Path("/opt") / name.capitalize() / f"{name}.py",
        Path.home() / name / f"{name}.py",
        # capitalised variants common on Kali
        Path.home() / "tools" / "LinkFinder"   / "linkfinder.py",
        Path.home() / "tools" / "SecretFinder" / "SecretFinder.py",
        Path("/opt/LinkFinder/linkfinder.py"),
        Path("/opt/SecretFinder/SecretFinder.py"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def _collect_js_urls(ctx: RunnerContext) -> list[str]:
    """Pull .js URLs from crawl and katana output."""
    sources = [
        ctx.out_dir / "crawl" / "all_urls.txt",
        ctx.out_dir / "crawl" / "katana.txt",
    ]
    js_urls = []
    for src in sources:
        for url in read_lines(src):
            if url.endswith(".js") or ".js?" in url:
                js_urls.append(url)
    # also include live hosts themselves as targets for inline JS scanning
    live_file = ctx.out_dir / "http_probe" / "live_hosts.txt"
    live_urls = read_lines(live_file) if live_file.exists() else []

    return list(dict.fromkeys(js_urls + live_urls))  # deduplicated, order preserved


def _run_linkfinder(
    script: str,
    url: str,
    out_file: Path,
) -> list[str]:
    """Run linkfinder against a single URL, return list of found endpoints."""
    rc, stdout, stderr = run(
        ["python3", script, "-i", url, "-o", "cli"],
        capture=True,
        timeout=60,
        silent=True,
    )
    endpoints = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith("[")]
    if endpoints:
        write_lines(out_file, endpoints)
    return endpoints


def _run_secretfinder(
    script: str,
    url: str,
    out_file: Path,
) -> list[str]:
    """Run secretfinder against a single URL, return list of secrets found."""
    rc, stdout, stderr = run(
        ["python3", script, "-i", url, "-o", "cli"],
        capture=True,
        timeout=60,
        silent=True,
    )
    secrets = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith("[")]
    if secrets:
        write_lines(out_file, secrets)
    return secrets


def run_js_analysis(ctx: RunnerContext) -> dict:
    d = ctx.module_dir("js_analysis")

    # ── resume check ──────────────────────────────────────────────────────────
    if ctx.is_done("js_analysis", "all_endpoints.txt"):
        info("js_analysis already complete — skipping (resume mode)")
        return {
            "endpoints": str(d / "all_endpoints.txt"),
            "secrets":   str(d / "all_secrets.txt"),
        }

    lf_script = _find_tool_path("linkfinder")
    sf_script  = _find_tool_path("secretfinder")

    if not lf_script and not sf_script:
        skipped("linkfinder + secretfinder", "neither installed")
        console.print(
            "  [dim]install linkfinder : pip install linkfinder  OR  "
            "git clone https://github.com/GerbenJavado/LinkFinder[/dim]"
        )
        console.print(
            "  [dim]install secretfinder: "
            "git clone https://github.com/m4ll0k/SecretFinder[/dim]"
        )
        return {}

    targets = _collect_js_urls(ctx)
    if not targets:
        warning("No JS URLs found to analyse")
        return {}

    # Cap to avoid hour-long runs
    cap = 200 if not ctx.stealth else 50
    if len(targets) > cap:
        info(f"Capping JS analysis at {cap} URLs (found {len(targets)})")
        targets = targets[:cap]

    js_urls_file = d / "js_urls.txt"
    write_lines(js_urls_file, targets)
    info(f"Analysing {len(targets)} JS / page URLs...")

    all_endpoints: list[str] = []
    all_secrets:   list[str] = []
    endpoint_files: list[Path] = []
    secret_files:   list[Path] = []

    for i, url in enumerate(targets):
        safe_name = url.replace("://", "_").replace("/", "_").replace(".", "_")[:80]

        if lf_script:
            ep_file = d / f"linkfinder_{i:04d}_{safe_name}.txt"
            endpoints = _run_linkfinder(lf_script, url, ep_file)
            if endpoints:
                all_endpoints.extend(endpoints)
                endpoint_files.append(ep_file)

        if sf_script:
            sec_file = d / f"secretfinder_{i:04d}_{safe_name}.txt"
            secrets = _run_secretfinder(sf_script, url, sec_file)
            if secrets:
                all_secrets.extend(secrets)
                secret_files.append(sec_file)

    # ── merged outputs ─────────────────────────────────────────────────────────
    endpoints_out = d / "all_endpoints.txt"
    secrets_out   = d / "all_secrets.txt"

    write_lines(endpoints_out, all_endpoints)
    write_lines(secrets_out, all_secrets)

    found("JS endpoints discovered", len(set(all_endpoints)), endpoints_out)

    if all_secrets:
        found("JS secrets found", len(set(all_secrets)), secrets_out)
        success(f"[bold red]JS SECRETS FOUND:[/bold red] {len(set(all_secrets))} hits → {secrets_out}")

        # also copy into secrets/ folder for unified visibility
        secrets_dir = ctx.module_dir("secrets")
        js_secrets_copy = secrets_dir / "js_secrets.txt"
        shutil.copy2(secrets_out, js_secrets_copy)
        info(f"Copied to secrets/js_secrets.txt for unified review")
    else:
        info("No secrets found in JS files")
        secrets_out.write_text("# No JS secrets found\n")

    return {
        "endpoints": str(endpoints_out),
        "secrets":   str(secrets_out),
        "endpoint_count": len(set(all_endpoints)),
        "secret_count":   len(set(all_secrets)),
    }
