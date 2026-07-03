"""CLI entry point for skillseraph."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .models import Platform, Severity
from .scanner import scan_directory

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


@click.command()
@click.argument("target", default=".", type=click.Path())
@click.option("--platform", "-p", type=click.Choice([p.value for p in Platform]), multiple=True, help="Target platform(s). Default: auto-detect.")
@click.option("--include-deps/--no-deps", default=True, help="Scan dependency trees (node_modules, vendor, etc.)")
@click.option("--json-out", "-j", type=click.Path(), help="Write JSON findings to file")
@click.option("--sarif", type=click.Path(), help="Write SARIF 2.1.0 report")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "any", "none"]), default="high", help="Exit non-zero if findings at this severity or above")
@click.option("--min-confidence", type=click.Choice(["low", "medium", "high"]), default="low", help="Suppress findings below this confidence level")
@click.option("--home", type=click.Path(exists=True, file_okay=False), help="Home directory to audit with the audit-local target")
@click.option("--output", type=click.Path(), help="Output directory for the demo-fixture target")
@click.option("--force", is_flag=True, help="Allow demo-fixture to replace a non-empty output directory")
@click.option("--baseline", type=click.Path(), help="Suppress findings recorded in this baseline file")
@click.option("--save-baseline", type=click.Path(), help="Write current findings as an accepted baseline and exit 0")
@click.option("--quiet", "-q", is_flag=True, help="Suppress console output (use with --json-out)")
@click.option("--changed-only", is_flag=True, help="Scan only changed files (reads list from stdin, one path per line)")
@click.option("--files-from", type=click.Path(), help="File containing changed paths (one per line); alternative to stdin for --changed-only")
@click.option("--generate-policy", type=click.Path(), help="Write a NullfieldPolicy YAML from findings (scan→enforce bridge)")
@click.option("--watch", "-w", is_flag=True, help="Watch mode: monitor for changes and re-scan continuously")
@click.option("--correlate/--no-correlate", default=True, help="Cross-file correlation (detect multi-file attack chains)")
@click.option("--version", "-V", is_flag=True, help="Show version")
def main(
    target: str,
    platform: tuple[str, ...],
    include_deps: bool,
    json_out: str | None,
    sarif: str | None,
    fail_on: str,
    min_confidence: str,
    home: str | None,
    output: str | None,
    force: bool,
    baseline: str | None,
    save_baseline: str | None,
    quiet: bool,
    changed_only: bool,
    files_from: str | None,
    generate_policy: str | None,
    watch: bool,
    correlate: bool,
    version: bool,
) -> None:
    """Scan agent configs for security issues across agentic platforms."""
    if version:
        click.echo(f"skillseraph {__version__}")
        return

    if target == "demo-fixture":
        from .demo import create_demo_fixture

        if not output:
            raise click.ClickException("demo-fixture requires --output <directory>")
        try:
            fixture = create_demo_fixture(Path(output), force=force)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        console.print(f"[green]Demo fixture written → {fixture.root}[/green]")
        console.print(f"  Repo fixture: {fixture.repo}")
        console.print(f"  Home fixture: {fixture.home}")
        console.print("  Try: skillseraph <fixture>/repo --fail-on none")
        console.print("  Try: skillseraph audit-local --home <fixture>/home --fail-on none")
        return

    if target == "smoke-test":
        from .demo import run_smoke_test

        try:
            checks = run_smoke_test()
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        console.print("[green bold]Smoke test passed[/green bold]")
        console.print("  Checks observed: " + ", ".join(sorted(checks)))
        return

    from .baseline import apply_baseline, load_baseline
    from .baseline import save_baseline as write_baseline

    platforms = [Platform(p) for p in platform] if platform else None
    audit_local = target == "audit-local"
    if audit_local:
        target_path = Path(home).resolve() if home else Path.home().resolve()
    else:
        target_path = Path(target).resolve()

    if not audit_local and not target_path.exists():
        raise click.ClickException(f"Target does not exist: {target}")

    # Watch mode: enter the polling loop and never return (until Ctrl-C or fail).
    if watch:
        from .watcher import watch_and_scan
        watch_and_scan(target_path, platforms=platforms, include_deps=include_deps, fail_on=fail_on, quiet=quiet)
        return  # unreachable (watch exits via sys.exit)

    changed: list[Path] | None = None
    if changed_only or files_from:
        if files_from:
            changed = [Path(ln.strip()) for ln in Path(files_from).read_text().splitlines() if ln.strip()]
        elif not sys.stdin.isatty():
            changed = [Path(ln.strip()) for ln in sys.stdin if ln.strip()]
        else:
            changed = []

    if audit_local:
        from .local_audit import audit_local_ide_configs
        result = audit_local_ide_configs(home=target_path)
    else:
        result = scan_directory(
            target_path,
            platforms=platforms,
            include_deps=include_deps,
            changed_files=changed,
        )

    if correlate:
        from .correlator import correlate as run_correlate
        result = run_correlate(result)

    if min_confidence != "low":
        levels = {"low": 0, "medium": 1, "high": 2}
        threshold = levels[min_confidence]
        result.findings = [
            f for f in result.findings
            if levels.get(f.confidence, 2) >= threshold
        ]

    if save_baseline:
        count = write_baseline(result, Path(save_baseline))
        if not quiet:
            console.print(f"[green]Wrote baseline with {count} accepted finding(s) → {save_baseline}[/green]")
        sys.exit(0)

    suppressed = 0
    if baseline:
        before = len(result.findings)
        result = apply_baseline(result, load_baseline(Path(baseline)))
        suppressed = before - len(result.findings)

    if not quiet:
        _print_results(result, fail_on)
        if suppressed:
            console.print(f"  [dim]({suppressed} finding(s) suppressed by baseline)[/dim]")

    if json_out:
        _write_json(result, Path(json_out))

    if sarif:
        _write_sarif(result, Path(sarif))

    if generate_policy:
        from .policy_gen import write_policy
        count = write_policy(result, Path(generate_policy))
        if not quiet:
            console.print(f"  [green]NullfieldPolicy written → {generate_policy} ({count} finding(s) mapped)[/green]")

    exit_code = _check_threshold(result, fail_on)
    sys.exit(exit_code)


def _print_results(result, fail_on: str) -> None:
    console.print()
    console.print(f"[bold]skillseraph v{__version__}[/bold] — agent config security scanner")
    console.print(f"  Target: {result.target}")
    console.print(f"  Platforms: {', '.join(p.value for p in result.platforms_detected)}")
    console.print(f"  Files scanned: {result.files_scanned}")
    console.print()

    if not result.findings:
        console.print("[green bold]✓ No findings[/green bold]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Sev", width=8)
    table.add_column("Check", width=24)
    table.add_column("Location", width=40)
    table.add_column("Title", min_width=30)

    for f in sorted(result.findings, key=lambda x: x.severity.score, reverse=True):
        sev_style = SEVERITY_COLORS.get(f.severity, "")
        table.add_row(
            f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
            f.check,
            f.location,
            f.title,
        )

    console.print(table)
    console.print()
    console.print(
        f"  [red]{result.critical_count} critical[/red]  "
        f"[red]{result.high_count} high[/red]  "
        f"[yellow]{sum(1 for f in result.findings if f.severity == Severity.MEDIUM)} medium[/yellow]  "
        f"[blue]{sum(1 for f in result.findings if f.severity == Severity.LOW)} low[/blue]  "
        f"risk_score={result.risk_score}"
    )
    console.print(f"  fail_on={fail_on}")
    console.print()


def _write_json(result, path: Path) -> None:
    data = {
        "version": __version__,
        "target": str(result.target),
        "platforms": [p.value for p in result.platforms_detected],
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score,
        "findings": [
            {
                "path": str(f.path),
                "line": f.line,
                "check": f.check,
                "severity": f.severity.value,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "platform": f.platform.value,
                "taxonomy_id": f.taxonomy_id,
                "atlas_id": f.atlas_id,
                "confidence": f.confidence,
            }
            for f in result.findings
        ],
    }
    path.write_text(json.dumps(data, indent=2))


def _write_sarif(result, path: Path) -> None:
    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "skillseraph",
                    "version": __version__,
                    "informationUri": "https://github.com/babywyrm/skillseraph",
                }
            },
            "results": [
                {
                    "ruleId": f.check,
                    "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}[f.severity.value],
                    "message": {"text": f"{f.title}: {f.detail}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(f.path.relative_to(result.target))},
                            "region": {"startLine": f.line or 1},
                        }
                    }],
                }
                for f in result.findings
            ],
        }],
    }
    path.write_text(json.dumps(sarif_doc, indent=2))


def _check_threshold(result, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "any": Severity.INFO,
    }[fail_on]
    for f in result.findings:
        if f.severity.score >= threshold.score:
            return 1
    return 0
