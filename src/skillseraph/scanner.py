"""Core scanner — orchestrates file discovery and check execution."""

from __future__ import annotations

from pathlib import Path

from .checks import run_all_checks
from .models import Finding, Platform, ScanResult
from .platforms import PLATFORMS, detect_platforms, get_all_patterns


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for agent config security issues."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []

    if not content.strip():
        return []

    return run_all_checks(path, content)


def scan_directory(
    target: Path,
    platforms: list[Platform] | None = None,
    include_deps: bool = True,
) -> ScanResult:
    """Scan a directory for agent config security issues across platforms."""
    target = target.resolve()

    if platforms is None:
        platforms = detect_platforms(str(target))

    patterns = get_all_patterns(platforms)
    if not include_deps:
        patterns = [p for p in patterns if not any(
            dep in p for dep in ("node_modules", "vendor", ".venv", "packages")
        )]

    files_to_scan: set[Path] = set()
    for pattern in patterns:
        files_to_scan.update(target.glob(pattern))

    all_findings: list[Finding] = []
    for fpath in sorted(files_to_scan):
        if fpath.is_file():
            findings = scan_file(fpath)
            for f in findings:
                if f.platform == Platform.GENERIC:
                    for p in platforms:
                        for pat in PLATFORMS[p].file_patterns:
                            if fpath.match(pat):
                                f.platform = p
                                break
            all_findings.extend(findings)

    return ScanResult(
        target=target,
        findings=all_findings,
        files_scanned=len(files_to_scan),
        platforms_detected=platforms,
    )
