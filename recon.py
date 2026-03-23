#!/usr/bin/env python3
"""
recon.py — Main orchestrator for the recon framework.
"""

import sys
import argparse
import time
from pathlib import Path
from datetime import datetime

from core.console import console, banner, section, success, error, info, warning
from core.config import OUTPUT_BASE, TOOL_REGISTRY, WORDLIST_REGISTRY
from core.checks import preflight_check
from core.runner import RunnerContext

from modules.subdomains import run_subdomain_enum
from modules.dns import run_dns
from modules.http_probe import run_http_probe
from modules.crawl import run_crawl
from modules.js_analysis import run_js_analysis
from modules.fuzzing import run_fuzzing
from modules.params import run_params
from modules.portscan import run_portscan
from modules.vulnscan import run_vulnscan
from modules.screenshots import run_screenshots
from modules.secrets import run_secrets
from modules.cloud import run_cloud


def parse_args():
    parser = argparse.ArgumentParser(
        description="recon — modular recon framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 recon.py -d example.com
  python3 recon.py -d example.com --stealth
  python3 recon.py -d example.com --resume
  python3 recon.py -d example.com --skip vulnscan screenshots
  python3 recon.py -d example.com --only subdomains dns http_probe
  python3 recon.py -d example.com --no-screenshots
        """,
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--skip",
        nargs="+",
        metavar="MODULE",
        default=[],
        help="Modules to skip",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="MODULE",
        default=[],
        help="Run only these modules (overrides --skip)",
    )
    parser.add_argument(
        "--no-screenshots",
        action="store_true",
        help="Disable gowitness screenshots (default: prompt user)",
    )
    parser.add_argument(
        "--screenshots",
        action="store_true",
        help="Enable gowitness screenshots without prompting",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override default output directory",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Thread count for tools that support it (default: 50)",
    )
    parser.add_argument(
        "--stealth",
        action="store_true",
        help="Stealth mode: halve thread counts, lower rate limits across all tools",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume: skip modules whose output files already exist (reuses previous run)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would run without executing",
    )
    return parser.parse_args()


ALL_MODULES = [
    "subdomains",
    "dns",
    "http_probe",
    "crawl",
    "js_analysis",
    "fuzzing",
    "params",
    "portscan",
    "vulnscan",
    "screenshots",
    "secrets",
    "cloud",
]

MODULE_MAP = {
    "subdomains":  run_subdomain_enum,
    "dns":         run_dns,
    "http_probe":  run_http_probe,
    "crawl":       run_crawl,
    "js_analysis": run_js_analysis,
    "fuzzing":     run_fuzzing,
    "params":      run_params,
    "portscan":    run_portscan,
    "vulnscan":    run_vulnscan,
    "screenshots": run_screenshots,
    "secrets":     run_secrets,
    "cloud":       run_cloud,
}

MODULE_DESCRIPTIONS = {
    "subdomains":  "Subdomain enumeration     (subfinder, amass, assetfinder)",
    "dns":         "DNS resolution & brute    (dnsx, massdns, zone-transfer)",
    "http_probe":  "HTTP probing              (httpx, wafw00f, whatweb)",
    "crawl":       "Crawling & URL harvest    (katana, gau, waybackurls)",
    "js_analysis": "JavaScript analysis       (linkfinder, secretfinder)",
    "fuzzing":     "Directory fuzzing         (ffuf, feroxbuster)",
    "params":      "Parameter discovery       (arjun)",
    "portscan":    "Port scanning             (nmap)",
    "vulnscan":    "Vulnerability scanning    (nuclei)  → triage report",
    "screenshots": "Screenshots               (gowitness) → correlated triage  [optional]",
    "secrets":     "Secret scanning           (trufflehog, gitleaks)",
    "cloud":       "Cloud asset enum          (cloud_enum)",
}


def prompt_screenshots() -> bool:
    """Ask user whether to run screenshots."""
    console.print("\n[bold yellow]❓  Run screenshots with gowitness?[/bold yellow] (can be slow for large scopes)")
    console.print("   [dim]y[/dim] = yes   [dim]n[/dim] = skip   [dim]Enter[/dim] = skip")
    try:
        ans = input("   › ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        return False


def prompt_nmap_options() -> str:
    """Let user pick nmap scan profile."""
    console.print("\n[bold yellow]❓  Choose nmap scan profile:[/bold yellow]")
    profiles = {
        "1": ("Quick top-1000",        "-T4 --open -F"),
        "2": ("Full port scan",        "-T4 --open -p-"),
        "3": ("Stealth SYN + version", "-T3 --open -sS -sV -p-"),
        "4": ("Service + script scan", "-T4 --open -sV -sC -p-"),
        "5": ("Custom", None),
    }
    for k, (label, flags) in profiles.items():
        flag_str = f"[dim]{flags}[/dim]" if flags else "[dim]enter your own flags[/dim]"
        console.print(f"   [{k}] {label}  {flag_str}")
    try:
        choice = input("   › ").strip()
        if choice in profiles:
            label, flags = profiles[choice]
            if flags is None:
                console.print("   Enter custom nmap flags:")
                flags = input("   › ").strip() or "-T4 --open -F"
            info(f"nmap profile: {label}  ({flags})")
            return flags
        else:
            warning("Invalid choice, defaulting to quick scan")
            return "-T4 --open -F"
    except (KeyboardInterrupt, EOFError):
        return "-T4 --open -F"


def print_module_plan(modules: list, stealth: bool = False, resume: bool = False):
    console.print()
    section("SCAN PLAN")
    for m in ALL_MODULES:
        status = "[green]✓[/green]" if m in modules else "[dim]✗  (skipped)[/dim]"
        console.print(f"   {status}  {MODULE_DESCRIPTIONS.get(m, m)}")
    flags = []
    if stealth:
        flags.append("[bold yellow]STEALTH[/bold yellow] (halved threads, lower rate limits)")
    if resume:
        flags.append("[bold cyan]RESUME[/bold cyan] (modules with existing output will be skipped)")
    for f in flags:
        console.print(f"\n   ⚑  {f}")
    console.print()


def main():
    banner()
    args = parse_args()
    domain = args.domain.strip().lower()

    # ── Output directory ──────────────────────────────────────────────────────
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = Path.home() / "Desktop" / f"{domain}-RECON"
    out_dir.mkdir(parents=True, exist_ok=True)
    info(f"Target  : [bold cyan]{domain}[/bold cyan]")
    info(f"Output  : [bold]{out_dir}[/bold]")
    if args.stealth:
        warning("Stealth mode ON — threads halved, rate limits lowered")
    if args.resume:
        info("Resume mode ON — completed modules will be skipped")

    # ── Screenshots decision ───────────────────────────────────────────────────
    if args.no_screenshots:
        want_screenshots = False
    elif args.screenshots:
        want_screenshots = True
    elif "screenshots" in args.skip:
        want_screenshots = False
    else:
        want_screenshots = prompt_screenshots()

    # ── Module selection ───────────────────────────────────────────────────────
    if args.only:
        selected = [m for m in args.only if m in ALL_MODULES]
    else:
        skip = set(args.skip)
        if not want_screenshots:
            skip.add("screenshots")
        selected = [m for m in ALL_MODULES if m not in skip]

    print_module_plan(selected, stealth=args.stealth, resume=args.resume)

    # ── Preflight checks ───────────────────────────────────────────────────────
    section("PREFLIGHT CHECKS")
    ok = preflight_check(selected)
    if not ok:
        error("Preflight failed. Fix the above issues and re-run.")
        sys.exit(1)
    success("All checks passed.")

    # ── nmap options (only if portscan is selected) ────────────────────────────
    nmap_flags = None
    if "portscan" in selected:
        nmap_flags = prompt_nmap_options()

    if args.dry_run:
        warning("--dry-run: no commands executed.")
        sys.exit(0)

    # ── Runner context shared across modules ───────────────────────────────────
    ctx = RunnerContext(
        domain=domain,
        out_dir=out_dir,
        threads=args.threads,
        nmap_flags=nmap_flags or "-T4 --open -F",
        dry_run=args.dry_run,
        stealth=args.stealth,
        resume=args.resume,
    )

    # ── Execute modules ────────────────────────────────────────────────────────
    start = time.time()
    results = {}

    for mod_name in selected:
        fn = MODULE_MAP[mod_name]
        section(mod_name.upper())
        try:
            mod_result = fn(ctx)
            results[mod_name] = mod_result
        except KeyboardInterrupt:
            warning(f"Module [bold]{mod_name}[/bold] interrupted by user — continuing...")
        except Exception as exc:
            error(f"Module [bold]{mod_name}[/bold] crashed: {exc}")
            import traceback
            console.print(f"  [dim]{traceback.format_exc()}[/dim]")
            results[mod_name] = None

    # ── Summary ────────────────────────────────────────────────────────────────
    elapsed = time.time() - start
    section("SUMMARY")
    console.print(f"   [bold]Domain  :[/bold] {domain}")
    console.print(f"   [bold]Duration:[/bold] {elapsed:.1f}s")
    console.print(f"   [bold]Output  :[/bold] {out_dir}")
    console.print()

    for mod_name, res in results.items():
        if res and isinstance(res, dict):
            for k, v in res.items():
                if v and k in ("triage", "findings", "secrets", "endpoints", "count"):
                    console.print(f"   [green]✓[/green] [bold]{mod_name}[/bold] / {k}: [cyan]{v}[/cyan]")

    success("Recon complete.")


if __name__ == "__main__":
    main()



def parse_args():
    parser = argparse.ArgumentParser(
        description="recon — modular recon framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 recon.py -d example.com
  python3 recon.py -d example.com --skip vulnscan screenshots
  python3 recon.py -d example.com --only subdomains dns http_probe
  python3 recon.py -d example.com --no-screenshots
        """,
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument(
        "--skip",
        nargs="+",
        metavar="MODULE",
        default=[],
        help="Modules to skip",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="MODULE",
        default=[],
        help="Run only these modules (overrides --skip)",
    )
    parser.add_argument(
        "--no-screenshots",
        action="store_true",
        help="Disable gowitness screenshots (default: prompt user)",
    )
    parser.add_argument(
        "--screenshots",
        action="store_true",
        help="Enable gowitness screenshots without prompting",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Override default output directory",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Thread count for tools that support it (default: 50)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would run without executing",
    )
    return parser.parse_args()


ALL_MODULES = [
    "subdomains",
    "dns",
    "http_probe",
    "crawl",
    "fuzzing",
    "params",
    "portscan",
    "vulnscan",
    "screenshots",
    "secrets",
    "cloud",
]

MODULE_MAP = {
    "subdomains": run_subdomain_enum,
    "dns": run_dns,
    "http_probe": run_http_probe,
    "crawl": run_crawl,
    "fuzzing": run_fuzzing,
    "params": run_params,
    "portscan": run_portscan,
    "vulnscan": run_vulnscan,
    "screenshots": run_screenshots,
    "secrets": run_secrets,
    "cloud": run_cloud,
}

MODULE_DESCRIPTIONS = {
    "subdomains":  "Subdomain enumeration     (subfinder, amass, assetfinder)",
    "dns":         "DNS resolution & brute    (dnsx, massdns, zone-transfer)",
    "http_probe":  "HTTP probing              (httpx, wafw00f, whatweb)",
    "crawl":       "Crawling & URL harvest    (katana, gau, waybackurls)",
    "fuzzing":     "Directory fuzzing         (ffuf, feroxbuster)",
    "params":      "Parameter discovery       (arjun)",
    "portscan":    "Port scanning             (nmap)",
    "vulnscan":    "Vulnerability scanning    (nuclei)",
    "screenshots": "Screenshots               (gowitness)  [optional]",
    "secrets":     "Secret scanning           (trufflehog, gitleaks)",
    "cloud":       "Cloud asset enum          (cloud_enum)",
}


def prompt_screenshots() -> bool:
    """Ask user whether to run screenshots."""
    console.print("\n[bold yellow]❓  Run screenshots with gowitness?[/bold yellow] (can be slow for large scopes)")
    console.print("   [dim]y[/dim] = yes   [dim]n[/dim] = skip   [dim]Enter[/dim] = skip")
    try:
        ans = input("   › ").strip().lower()
        return ans in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        return False


def prompt_nmap_options() -> str:
    """Let user pick nmap scan profile."""
    console.print("\n[bold yellow]❓  Choose nmap scan profile:[/bold yellow]")
    profiles = {
        "1": ("Quick top-1000", "-T4 --open -F"),
        "2": ("Full port scan", "-T4 --open -p-"),
        "3": ("Stealth SYN + version", "-T4 --open -sS -sV -p-"),
        "4": ("Service + script scan", "-T4 --open -sV -sC -p-"),
        "5": ("Custom", None),
    }
    for k, (label, flags) in profiles.items():
        flag_str = f"[dim]{flags}[/dim]" if flags else "[dim]enter your own flags[/dim]"
        console.print(f"   [{k}] {label}  {flag_str}")
    try:
        choice = input("   › ").strip()
        if choice in profiles:
            label, flags = profiles[choice]
            if flags is None:
                console.print("   Enter custom nmap flags:")
                flags = input("   › ").strip() or "-T4 --open -F"
            info(f"nmap profile: {label}  ({flags})")
            return flags
        else:
            warning("Invalid choice, defaulting to quick scan")
            return "-T4 --open -F"
    except (KeyboardInterrupt, EOFError):
        return "-T4 --open -F"


def print_module_plan(modules: list):
    console.print()
    section("SCAN PLAN")
    for m in ALL_MODULES:
        status = "[green]✓[/green]" if m in modules else "[dim]✗  (skipped)[/dim]"
        console.print(f"   {status}  {MODULE_DESCRIPTIONS.get(m, m)}")
    console.print()


def main():
    banner()
    args = parse_args()
    domain = args.domain.strip().lower()

    # ── Output directory ──────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = Path.home() / "Desktop" / f"{domain}-RECON"
    out_dir.mkdir(parents=True, exist_ok=True)
    info(f"Target  : [bold cyan]{domain}[/bold cyan]")
    info(f"Output  : [bold]{out_dir}[/bold]")

    # ── Screenshots decision ───────────────────────────────────────────────────
    if args.no_screenshots:
        want_screenshots = False
    elif args.screenshots:
        want_screenshots = True
    elif "screenshots" in args.skip:
        want_screenshots = False
    else:
        want_screenshots = prompt_screenshots()

    # ── Module selection ───────────────────────────────────────────────────────
    if args.only:
        selected = [m for m in args.only if m in ALL_MODULES]
    else:
        skip = set(args.skip)
        if not want_screenshots:
            skip.add("screenshots")
        selected = [m for m in ALL_MODULES if m not in skip]

    print_module_plan(selected)

    # ── Preflight checks ───────────────────────────────────────────────────────
    section("PREFLIGHT CHECKS")
    ok = preflight_check(selected)
    if not ok:
        error("Preflight failed. Fix the above issues and re-run.")
        sys.exit(1)
    success("All checks passed.")

    # ── nmap options (only if portscan is selected) ────────────────────────────
    nmap_flags = None
    if "portscan" in selected:
        nmap_flags = prompt_nmap_options()

    if args.dry_run:
        warning("--dry-run: no commands executed.")
        sys.exit(0)

    # ── Runner context shared across modules ───────────────────────────────────
    ctx = RunnerContext(
        domain=domain,
        out_dir=out_dir,
        threads=args.threads,
        nmap_flags=nmap_flags or "-T4 --open -F",
        dry_run=args.dry_run,
    )

    # ── Execute modules ────────────────────────────────────────────────────────
    start = time.time()
    results = {}

    for mod_name in selected:
        fn = MODULE_MAP[mod_name]
        section(mod_name.upper())
        try:
            mod_result = fn(ctx)
            results[mod_name] = mod_result
        except KeyboardInterrupt:
            warning(f"Module [bold]{mod_name}[/bold] interrupted by user — continuing...")
        except Exception as exc:
            error(f"Module [bold]{mod_name}[/bold] crashed: {exc}")
            results[mod_name] = None

    # ── Summary ────────────────────────────────────────────────────────────────
    elapsed = time.time() - start
    section("SUMMARY")
    console.print(f"   [bold]Domain  :[/bold] {domain}")
    console.print(f"   [bold]Duration:[/bold] {elapsed:.1f}s")
    console.print(f"   [bold]Output  :[/bold] {out_dir}")
    console.print()

    for mod_name, res in results.items():
        if res and isinstance(res, dict):
            for k, v in res.items():
                if v:
                    console.print(f"   [green]✓[/green] {mod_name}/{k}: [cyan]{v}[/cyan]")

    success("Recon complete.")


if __name__ == "__main__":
    main()
