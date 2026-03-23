"""
core/runner.py — Subprocess execution wrapper and shared RunnerContext.
"""

from __future__ import annotations

import subprocess
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .console import console, cmd_echo, error, warning


@dataclass
class RunnerContext:
    domain: str
    out_dir: Path
    threads: int = 50
    nmap_flags: str = "-T4 --open -F"
    dry_run: bool = False
    stealth: bool = False   # slow down tools, randomise order, lower concurrency
    resume: bool = False    # skip modules whose output files already exist

    # populated by modules as they run
    live_hosts: list[str] = field(default_factory=list)
    live_urls: list[str] = field(default_factory=list)
    all_subdomains: list[str] = field(default_factory=list)
    resolved_subdomains: list[str] = field(default_factory=list)

    def module_dir(self, name: str) -> Path:
        d = self.out_dir / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def file(self, module: str, filename: str) -> Path:
        return self.module_dir(module) / filename

    def effective_threads(self, cap: int = 9999) -> int:
        """Return thread count, halved in stealth mode, capped at cap."""
        t = self.threads // 2 if self.stealth else self.threads
        return max(1, min(t, cap))

    def is_done(self, module: str, sentinel_file: str) -> bool:
        """Return True if resume mode is on and the sentinel output file exists and is non-empty."""
        if not self.resume:
            return False
        p = self.out_dir / module / sentinel_file
        return p.exists() and p.stat().st_size > 0


def run(
    cmd: str | list[str],
    *,
    capture: bool = False,
    timeout: int = 1800,
    cwd: Optional[Path] = None,
    env=None,
    silent: bool = False,
) -> tuple[int, str, str]:
    """
    Execute a command.

    Returns (returncode, stdout, stderr).
    On timeout or error the returncode will be non-zero.
    """
    if isinstance(cmd, str):
        args = shlex.split(cmd)
        display = cmd
    else:
        args = cmd
        display = " ".join(str(a) for a in args)

    if not silent:
        cmd_echo(display)

    start = time.time()
    try:
        proc = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
        elapsed = time.time() - start
        if not silent:
            status = "[green]ok[/green]" if proc.returncode == 0 else f"[red]exit {proc.returncode}[/red]"
            console.print(f"  [dim]↳ done in {elapsed:.1f}s  {status}[/dim]")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        warning(f"Command timed out after {timeout}s: {display}")
        return 124, "", "timeout"
    except FileNotFoundError:
        error(f"Binary not found: {args[0]}")
        return 127, "", f"not found: {args[0]}"
    except Exception as exc:
        error(f"Unexpected error running [{display}]: {exc}")
        return 1, "", str(exc)


def run_piped(
    cmd1: str | list[str],
    cmd2: str | list[str],
    *,
    outfile: Optional[Path] = None,
    timeout: int = 1800,
) -> tuple[int, str]:
    """Run cmd1 | cmd2 using shell pipe, optionally writing to outfile."""
    if isinstance(cmd1, list):
        cmd1 = " ".join(shlex.quote(str(a)) for a in cmd1)
    if isinstance(cmd2, list):
        cmd2 = " ".join(shlex.quote(str(a)) for a in cmd2)

    if outfile:
        shell_cmd = f"{cmd1} | {cmd2} > {shlex.quote(str(outfile))}"
    else:
        shell_cmd = f"{cmd1} | {cmd2}"

    cmd_echo(shell_cmd)
    try:
        result = subprocess.run(
            shell_cmd,
            shell=True,
            capture_output=not outfile,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout or ""
    except subprocess.TimeoutExpired:
        warning(f"Pipe timed out after {timeout}s")
        return 124, ""
    except Exception as exc:
        error(f"Pipe error: {exc}")
        return 1, ""


def read_lines(path: Path) -> list[str]:
    """Read non-empty lines from a file, return list."""
    if not path or not path.exists():
        return []
    try:
        return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
    except Exception:
        return []


def write_lines(path: Path, lines: list[str]):
    """Write deduplicated sorted lines to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted(set(lines))
    path.write_text("\n".join(unique) + "\n")
    return unique


def merge_files(sources: list[Path], dest: Path) -> list[str]:
    """Merge multiple line-based files into one deduplicated file."""
    combined = []
    for src in sources:
        combined.extend(read_lines(src))
    return write_lines(dest, combined)
