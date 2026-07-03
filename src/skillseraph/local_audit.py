"""Local developer IDE config audit support."""

from __future__ import annotations

from pathlib import Path

from .models import Finding, Platform, ScanResult
from .scanner import scan_file


LOCAL_IDE_FILES: dict[Platform, tuple[str, ...]] = {
    Platform.VSCODE: (
        "Library/Application Support/Code/User/settings.json",
        "Library/Application Support/Code/User/tasks.json",
        "Library/Application Support/Code/User/keybindings.json",
        "Library/Application Support/Code/User/snippets",
        ".config/Code/User/settings.json",
        ".config/Code/User/tasks.json",
        ".config/Code/User/keybindings.json",
        ".config/Code/User/snippets",
        ".vscode/extensions",
    ),
    Platform.CURSOR: (
        "Library/Application Support/Cursor/User/settings.json",
        "Library/Application Support/Cursor/User/tasks.json",
        "Library/Application Support/Cursor/User/keybindings.json",
        "Library/Application Support/Cursor/User/snippets",
        ".config/Cursor/User/settings.json",
        ".config/Cursor/User/tasks.json",
        ".config/Cursor/User/keybindings.json",
        ".config/Cursor/User/snippets",
        ".cursor/extensions",
    ),
    Platform.WINDSURF: (
        "Library/Application Support/Windsurf/User/settings.json",
        "Library/Application Support/Windsurf/User/tasks.json",
        "Library/Application Support/Windsurf/User/keybindings.json",
        "Library/Application Support/Windsurf/User/snippets",
        ".config/Windsurf/User/settings.json",
        ".config/Windsurf/User/tasks.json",
        ".config/Windsurf/User/keybindings.json",
        ".config/Windsurf/User/snippets",
        ".windsurf/extensions",
    ),
}


def _iter_existing_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if root.is_dir():
        # Extension trees hold thousands of files per extension; only the
        # manifests carry the config we audit.
        if root.name == "extensions":
            return sorted(root.glob("*/package.json"))
        return sorted(path for path in root.rglob("*") if path.is_file())
    return []


def audit_local_ide_configs(home: Path | None = None) -> ScanResult:
    """Audit user-level IDE configuration files on the local machine.

    The audit intentionally stays static and file-scoped. It reads known
    VS Code-compatible user config locations, runs the normal scanner checks,
    and returns findings without collecting unrelated workstation state.
    """
    target = (home or Path.home()).resolve()
    findings: list[Finding] = []
    files_scanned = 0
    platforms_detected: list[Platform] = []

    for platform, rel_paths in LOCAL_IDE_FILES.items():
        platform_seen = False
        for rel_path in rel_paths:
            for path in _iter_existing_files(target / rel_path):
                files_scanned += 1
                platform_seen = True
                for finding in scan_file(path):
                    finding.platform = platform
                    findings.append(finding)
        if platform_seen:
            platforms_detected.append(platform)

    return ScanResult(
        target=target,
        findings=findings,
        files_scanned=files_scanned,
        platforms_detected=platforms_detected or [Platform.GENERIC],
    )
