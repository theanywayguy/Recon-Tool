"""
core/checks.py — Preflight checks: tool availability and wordlist existence.
"""

import shutil
from pathlib import Path

from .console import console, success, error, warning, info
from .config import (
    TOOL_REGISTRY,
    WORDLIST_REGISTRY,
    MODULE_TOOL_REQUIREMENTS,
    MODULE_WORDLIST_REQUIREMENTS,
    resolve_wordlist,
)


def check_tool(tool_key: str) -> bool:
    """Return True if the tool binary is on PATH."""
    binary, _ = TOOL_REGISTRY[tool_key]
    return shutil.which(binary) is not None


def print_tool_status(tool_key: str, required: bool) -> bool:
    binary, install_hint = TOOL_REGISTRY[tool_key]
    found = shutil.which(binary) is not None
    tag = "[red]required[/red]" if required else "[dim]optional[/dim]"
    if found:
        console.print(f"  [green]✓[/green]  [bold]{binary}[/bold]  ({tag})")
    else:
        if required:
            console.print(
                f"  [red]✗[/red]  [bold]{binary}[/bold]  ({tag})\n"
                f"       [dim]install: {install_hint}[/dim]"
            )
        else:
            console.print(
                f"  [yellow]○[/yellow]  [bold]{binary}[/bold]  ({tag}) — skipped if missing\n"
                f"       [dim]install: {install_hint}[/dim]"
            )
    return found


def print_wordlist_status(wl_key: str, required: bool) -> bool:
    rel, description, download_hint = WORDLIST_REGISTRY[wl_key]
    path = resolve_wordlist(wl_key)
    if path:
        console.print(f"  [green]✓[/green]  wordlist:[bold]{wl_key}[/bold]  →  [dim]{path}[/dim]")
        return True
    else:
        tag = "[red]required[/red]" if required else "[dim]optional[/dim]"
        console.print(
            f"  [red]✗[/red]  wordlist:[bold]{wl_key}[/bold]  ({tag})  — [dim]{description}[/dim]\n"
            f"       [dim]download SecLists from {download_hint}[/dim]\n"
            f"       [dim]expected at e.g. /usr/share/seclists/{rel}[/dim]"
        )
        return False


def preflight_check(selected_modules: list[str]) -> bool:
    """
    Run preflight checks for all selected modules.
    Returns True if all hard requirements are met.
    """
    all_ok = True

    for mod in selected_modules:
        reqs = MODULE_TOOL_REQUIREMENTS.get(mod, {})
        required_tools = reqs.get("required", [])
        optional_tools = reqs.get("optional", [])
        note = reqs.get("note", None)

        wl_keys = MODULE_WORDLIST_REQUIREMENTS.get(mod, [])

        if not required_tools and not optional_tools and not wl_keys:
            continue

        console.print(f"  [bold white]{mod}[/bold white]")

        # Required tools
        for t in required_tools:
            ok = print_tool_status(t, required=True)
            if not ok:
                all_ok = False

        # Optional tools (at least one must be present if there are no required)
        optional_found = []
        for t in optional_tools:
            ok = print_tool_status(t, required=False)
            if ok:
                optional_found.append(t)

        if optional_tools and not optional_found:
            error(f"No optional tools found for [bold]{mod}[/bold]. {note or 'At least one is required.'}")
            all_ok = False

        # Wordlists
        for wl_key in wl_keys:
            ok = print_wordlist_status(wl_key, required=True)
            if not ok:
                all_ok = False

        console.print()

    return all_ok


def get_available_tools(tool_keys: list[str]) -> list[str]:
    """Return subset of tool_keys that are available on PATH."""
    return [k for k in tool_keys if check_tool(k)]


def require_one_of(tool_keys: list[str]) -> list[str]:
    """Return available tools from list; caller should check len > 0."""
    return get_available_tools(tool_keys)
