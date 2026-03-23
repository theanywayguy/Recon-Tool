"""
core/console.py — Rich console helpers, banner, and print utilities.
"""

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.rule import Rule
from rich import box

console = Console()

_BANNER = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""


def banner():
    console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
    console.print(
        "  [dim]modular recon framework — subdomains · dns · http · crawl · fuzz · vuln · secrets[/dim]\n"
    )


def section(title: str):
    console.print()
    console.rule(f"[bold white] {title} [/bold white]", style="cyan")
    console.print()


def success(msg: str):
    console.print(f"  [bold green]✓[/bold green]  {msg}")


def error(msg: str):
    console.print(f"  [bold red]✗[/bold red]  {msg}")


def warning(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def info(msg: str):
    console.print(f"  [bold blue]→[/bold blue]  {msg}")


def cmd_echo(cmd: str):
    console.print(f"  [dim]$ {cmd}[/dim]")


def found(label: str, count: int, path=None):
    path_str = f"  → [cyan]{path}[/cyan]" if path else ""
    console.print(f"  [bold green]✓[/bold green]  {label}: [bold white]{count}[/bold white] results{path_str}")


def skipped(tool: str, reason: str = "not installed"):
    console.print(f"  [dim]⊘  {tool} — {reason}[/dim]")
