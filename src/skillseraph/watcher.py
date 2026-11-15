"""Watch mode — monitors a directory for changes and re-scans on modification.

Designed for sidecar or development use: agent workloads that fetch configs at
runtime, or developers who want continuous feedback as they edit agent configs.

Usage:
    skillseraph . --watch                  # watch + scan on change
    skillseraph . --watch --fail-on high   # exit non-zero if findings appear
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from .models import Platform
from .scanner import _matching_files, scan_directory

console = Console()

# Polling interval (seconds). We use polling rather than inotify/fsevents for
# maximum portability (works in containers, on NFS, inside K8s volumes).
_POLL_INTERVAL = float(os.environ.get("SKILLSERAPH_WATCH_INTERVAL", "2.0"))


def watch_and_scan(
    target: Path,
    platforms: list[Platform] | None = None,
    include_deps: bool = True,
    fail_on: str = "high",
    quiet: bool = False,
    correlate: bool = True,
) -> None:
    """Poll for filesystem changes and re-scan when agent config files change.

    Exits with code 1 as soon as a scan has findings at/above `fail_on`
    (sidecar mode). Results print only when the finding count changes.
    """
    from .cli import _check_threshold, _print_results
    from .correlator import correlate as run_correlate

    if not quiet:
        console.print(f"[bold]skillseraph --watch[/bold] monitoring {escape(str(target))}")
        console.print(f"  poll interval: {_POLL_INTERVAL}s | fail_on: {fail_on}")
        console.print(f"  platforms: {[p.value for p in platforms] if platforms else 'auto-detect'}")
        console.print()

    # Track file modification times.
    last_mtimes: dict[str, float] = {}
    last_finding_count = -1

    try:
        while True:
            changed = _poll_changes(target, last_mtimes, platforms, include_deps)
            if changed or last_finding_count == -1:
                if changed and not quiet:
                    names = escape(", ".join(p.name for p in changed[:5]))
                    console.print(f"[dim]  changed: {names}{'…' if len(changed) > 5 else ''}[/dim]")

                result = scan_directory(
                    target,
                    platforms=platforms,
                    include_deps=include_deps,
                    governed=fail_on != "none",
                )
                if correlate:
                    result = run_correlate(result)

                count_changed = len(result.findings) != last_finding_count
                last_finding_count = len(result.findings)
                if count_changed and not quiet:
                    _print_results(result, fail_on)
                if _check_threshold(result, fail_on) != 0:
                    if not quiet:
                        console.print("[red bold]Findings at/above threshold — exiting non-zero.[/red bold]")
                    sys.exit(1)
                if not count_changed and not quiet and changed:
                    console.print(f"  [dim]no new findings ({last_finding_count} total)[/dim]")

            time.sleep(_POLL_INTERVAL)
    except KeyboardInterrupt:
        if not quiet:
            console.print("\n[dim]watch stopped.[/dim]")


def _poll_changes(
    target: Path,
    last_mtimes: dict[str, float],
    platforms: list[Platform] | None,
    include_deps: bool,
) -> list[Path]:
    """Return files whose mtime changed since last check."""
    from .platforms import detect_platforms, get_all_patterns

    if platforms is None:
        platforms = detect_platforms(str(target))

    patterns = get_all_patterns(platforms)
    if not include_deps:
        patterns = [p for p in patterns if not any(
            dep in p for dep in ("node_modules", "vendor", ".venv", "packages")
        )]

    changed: list[Path] = []
    current_mtimes: dict[str, float] = {}

    for fpath in sorted(_matching_files(target, patterns)):
        key = str(fpath)
        try:
            mtime = fpath.stat().st_mtime
        except OSError:
            continue
        current_mtimes[key] = mtime
        if key not in last_mtimes or last_mtimes[key] != mtime:
            changed.append(fpath)

    last_mtimes.clear()
    last_mtimes.update(current_mtimes)
    return changed
