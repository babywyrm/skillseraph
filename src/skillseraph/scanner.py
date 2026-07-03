"""Core scanner — orchestrates file discovery and check execution."""

from __future__ import annotations

import re
from pathlib import Path

from .checks import run_all_checks
from .models import Finding, Platform, ScanResult
from .platforms import PLATFORMS, detect_platforms, get_all_patterns

_INLINE_IGNORE = re.compile(r"skillseraph:\s*ignore\s+([A-Za-z0-9_,-]+)")

IGNORE_FILE_NAME = ".skillseraphignore"


def _inline_ignores(content: str) -> dict[int, set[str]]:
    """Map line number → rule ids suppressed by an inline ignore comment."""
    ignores: dict[int, set[str]] = {}
    for line_num, line in enumerate(content.splitlines(), 1):
        match = _INLINE_IGNORE.search(line)
        if match:
            ignores[line_num] = {r.strip() for r in match.group(1).split(",") if r.strip()}
    return ignores


def load_ignore_file(target: Path) -> tuple[list[str], set[str]]:
    """Load .skillseraphignore from the target root.

    Returns (path_globs, ignored_rule_ids). Lines starting with `rule:` disable
    a rule repo-wide; all other non-comment lines are path globs.
    """
    ignore_path = target / IGNORE_FILE_NAME
    if not ignore_path.is_file():
        return [], set()

    path_globs: list[str] = []
    ignored_rules: set[str] = set()
    for raw in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("rule:"):
            ignored_rules.add(line.removeprefix("rule:").strip())
        else:
            path_globs.append(line)
    return path_globs, ignored_rules


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for agent config security issues."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return []

    if not content.strip():
        return []

    findings = run_all_checks(path, content)

    ignores = _inline_ignores(content)
    if ignores:
        findings = [
            f for f in findings
            if f.line is None or f.check not in ignores.get(f.line, set())
        ]
    return findings


def scan_directory(
    target: Path,
    platforms: list[Platform] | None = None,
    include_deps: bool = True,
    changed_files: list[Path] | None = None,
) -> ScanResult:
    """Scan a directory for agent config security issues across platforms.

    If *changed_files* is provided, only those files (that also match platform
    patterns) are scanned — this enables fast PR-diff gates.
    """
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

    ignore_globs, ignored_rules = load_ignore_file(target)
    if ignore_globs:
        files_to_scan = {
            f for f in files_to_scan
            if not any(f.relative_to(target).match(g) for g in ignore_globs)
        }

    if changed_files is not None:
        resolved_changed = {(target / f).resolve() for f in changed_files}
        files_to_scan = files_to_scan & resolved_changed

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

    if ignored_rules:
        all_findings = [f for f in all_findings if f.check not in ignored_rules]

    return ScanResult(
        target=target,
        findings=all_findings,
        files_scanned=len(files_to_scan),
        platforms_detected=platforms,
    )
