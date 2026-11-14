"""Core scanner — orchestrates file discovery and check execution."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path

from .checks import redact, run_all_checks
from .models import AcceptedException, Finding, Platform, ScanResult, Severity
from .platforms import PLATFORMS, detect_platforms, get_all_patterns

# ponytail: metadata must be reason, owner, until in that order. Any other
# shape fails closed when governed=True. A real grammar can wait until a
# second shape shows up.
_RULE_ID = r"[A-Za-z0-9_-]+"
_OWNER = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_META = rf'reason="([^"]*)"\s+owner=({_OWNER})\s+until=(\d{{4}}-\d{{2}}-\d{{2}})'
_INLINE_IGNORE = re.compile(
    rf"skillseraph:\s*ignore\s+({_RULE_ID}(?:,{_RULE_ID})*)(?:\s+{_META})?"
)
_META_ONLY = re.compile(_META)

IGNORE_FILE_NAME = ".skillseraphignore"
MAX_FILE_BYTES = 4 * 1024 * 1024


def read_capped(path: Path) -> tuple[str, bool]:
    """Text of the first MAX_FILE_BYTES of *path*, and whether the file was longer."""
    with path.open("rb") as handle:
        data = handle.read(MAX_FILE_BYTES + 1)
    return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace"), len(data) > MAX_FILE_BYTES

_IgnoreEntry = tuple[str, str, str, date | None]


def _as_of(today: date | None) -> date:
    return today or datetime.now(UTC).date()


def _parse_until(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _accepted(
    reason: str,
    owner: str,
    until: date | None,
    *,
    governed: bool,
    today: date,
) -> bool:
    if not governed:
        return True
    return bool(reason) and bool(owner) and until is not None and until >= today


def _inline_ignores(
    content: str,
    *,
    governed: bool,
    today: date,
    exceptions: list[AcceptedException] | None,
) -> dict[int, set[str]]:
    """Map line number → rule ids this scan will actually suppress."""
    ignores: dict[int, set[str]] = {}
    for line_num, line in enumerate(content.splitlines(), 1):
        match = _INLINE_IGNORE.search(line)
        if not match:
            continue
        rules = [rule for rule in match.group(1).split(",") if rule]
        reason = (match.group(2) or "").strip()
        owner = match.group(3) or ""
        until = _parse_until(match.group(4))
        if not _accepted(reason, owner, until, governed=governed, today=today):
            continue
        ignores[line_num] = set(rules)
        if governed and exceptions is not None and until is not None:
            for rule in rules:
                exceptions.append(AcceptedException(
                    kind="rule",
                    scope=rule,
                    reason=reason,
                    owner=owner,
                    until=until.isoformat(),
                    line=line_num,
                ))
    return ignores


def _parse_scoped_line(prefix: str, line: str) -> _IgnoreEntry | None:
    body = line.removeprefix(prefix)
    scope, _, rest = body.partition(" ")
    if not scope or not re.fullmatch(_RULE_ID if prefix == "rule:" else r"\S+", scope):
        return None
    rest = rest.strip()
    if not rest:
        return scope, "", "", None
    meta = _META_ONLY.fullmatch(rest)
    if not meta:
        return scope, "", "", None
    return scope, meta.group(1).strip(), meta.group(2), _parse_until(meta.group(3))


def load_ignore_file(target: Path) -> tuple[list[_IgnoreEntry], list[_IgnoreEntry]]:
    """Load .skillseraphignore from the target root.

    Returns (path_entries, rule_entries). Each entry is
    (scope, reason, owner, until). Bare lines carry an empty reason.
    """
    ignore_path = target / IGNORE_FILE_NAME
    if not ignore_path.is_file():
        return [], []

    path_entries: list[_IgnoreEntry] = []
    rule_entries: list[_IgnoreEntry] = []
    for raw in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("rule:"):
            parsed = _parse_scoped_line("rule:", line)
            if parsed:
                rule_entries.append(parsed)
            continue
        if line.startswith("path:"):
            parsed = _parse_scoped_line("path:", line)
            if parsed:
                path_entries.append(parsed)
            continue
        path_entries.append((line, "", "", None))
    return path_entries, rule_entries


def _record(
    entries: list[_IgnoreEntry],
    *,
    kind: str,
    governed: bool,
    today: date,
    exceptions: list[AcceptedException],
) -> list[str]:
    honored: list[str] = []
    for scope, reason, owner, until in entries:
        if not _accepted(reason, owner, until, governed=governed, today=today):
            continue
        honored.append(scope)
        if governed and until is not None:
            exceptions.append(AcceptedException(
                kind=kind,
                scope=scope,
                reason=reason,
                owner=owner,
                until=until.isoformat(),
                path=IGNORE_FILE_NAME,
            ))
    return honored


def scan_file(
    path: Path,
    *,
    governed: bool = False,
    today: date | None = None,
    exceptions: list[AcceptedException] | None = None,
) -> list[Finding]:
    """Scan a single file for agent config security issues.

    When *governed* is set, an inline suppression counts only with a non-empty
    reason, a role id in *owner*, and an *until* date that is today or later.
    """
    try:
        content, truncated = read_capped(path)
    except OSError:
        return []

    if not content.strip():
        return []

    findings = run_all_checks(path, content)
    if truncated:
        findings.append(Finding(
            path=path,
            check="agent_config_oversized",
            severity=Severity.HIGH,
            title="Agent config is too large to scan fully",
            detail=(
                f"Only the first {MAX_FILE_BYTES} bytes were checked. Agent config this "
                "large is unusual, and padding is a way to push a payload past scanners."
            ),
            evidence=f"larger than {MAX_FILE_BYTES} bytes",
            taxonomy_id="MCP-T13",
            atlas_id="J8",
            confidence="medium",
        ))
    for f in findings:
        f.evidence, f.detail = redact(f.evidence), redact(f.detail)
    ignores = _inline_ignores(
        content,
        governed=governed,
        today=_as_of(today),
        exceptions=exceptions,
    )
    if ignores:
        findings = [
            f for f in findings
            if f.line is None or f.check not in ignores.get(f.line, set())
        ]
    return findings


def _matching_files(target: Path, patterns: list[str]) -> set[Path]:
    """Expand platform globs to files.

    ponytail: a trailing ``**`` matches only the directory on Python 3.12 and
    the directory plus its files on 3.13. Walk matched directories so both
    versions scan the same files. A dedicated glob wrapper can replace this
    if the patterns grow a real grammar.
    """
    files: set[Path] = set()
    for pattern in patterns:
        for match in target.glob(pattern):
            if match.is_file():
                files.add(match)
            elif match.is_dir():
                files.update(path for path in match.rglob("*") if path.is_file())
    return files


def scan_directory(
    target: Path,
    platforms: list[Platform] | None = None,
    include_deps: bool = True,
    changed_files: list[Path] | None = None,
    governed: bool = False,
    today: date | None = None,
) -> ScanResult:
    """Scan a directory for agent config security issues across platforms.

    If *changed_files* is provided, only those files (that also match platform
    patterns) are scanned — this enables fast PR-diff gates.

    When *governed* is set, path globs and `rule:` lines count only with a
    reason, a role id, and an unexpired `until` date. Bare entries stay in
    effect for an ungoverned scan.
    """
    target = target.resolve()
    as_of = _as_of(today)

    if platforms is None:
        platforms = detect_platforms(str(target))

    patterns = get_all_patterns(platforms)
    if not include_deps:
        patterns = [p for p in patterns if not any(
            dep in p for dep in ("node_modules", "vendor", ".venv", "packages")
        )]

    files_to_scan = _matching_files(target, patterns)

    path_entries, rule_entries = load_ignore_file(target)
    exceptions: list[AcceptedException] = []
    ignore_globs = _record(
        path_entries, kind="path", governed=governed, today=as_of, exceptions=exceptions,
    )
    ignored_rules = set(_record(
        rule_entries, kind="rule", governed=governed, today=as_of, exceptions=exceptions,
    ))
    if ignore_globs:
        files_to_scan = {
            f for f in files_to_scan
            if not any(f.relative_to(target).match(g) for g in ignore_globs)
        }

    if changed_files is not None:
        resolved_changed = {(target / f).resolve() for f in changed_files}
        files_to_scan = files_to_scan & resolved_changed

    escaped = {f for f in files_to_scan if not f.resolve().is_relative_to(target)}
    files_to_scan -= escaped
    all_findings: list[Finding] = [
        Finding(
            path=fpath,
            check="scan_symlink_outside_target",
            severity=Severity.HIGH,
            title="Agent config is a symlink to a file outside the repo",
            detail=(
                "The link was not followed. An agent that reads this path loads whatever "
                "file it points to on the reader's machine, such as credentials, into "
                "its context."
            ),
            evidence="symlink resolves outside the scanned tree",
            taxonomy_id="MCP-T12",
            atlas_id="J5",
            confidence="medium",
        )
        for fpath in sorted(escaped)
    ]
    for fpath in sorted(files_to_scan):
        if fpath.is_file():
            inline: list[AcceptedException] = []
            findings = scan_file(fpath, governed=governed, today=as_of, exceptions=inline)
            for exc in inline:
                exceptions.append(replace(exc, path=fpath.relative_to(target).as_posix()))
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
        exceptions=exceptions,
        scanned_paths=sorted(files_to_scan),
    )
