"""Local developer IDE config audit support."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .models import AcceptedException, Finding, Platform, ScanResult
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
        "Library/Application Support/Code/User/mcp.json",
        ".config/Code/User/mcp.json",
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
        ".cursor/mcp.json",
        ".cursor/hooks.json",
        ".cursor/cli-config.json",
        ".cursor/argv.json",
    ),
    Platform.CODEX: (
        ".codex/config.toml",
        ".codex/hooks.json",
        ".codex/rules",
        ".codex/skills",
    ),
    Platform.CLAUDE: (
        ".claude/settings.json",
        ".claude/settings.local.json",
        ".claude/CLAUDE.md",
        "Library/Application Support/Claude/claude_desktop_config.json",
        ".config/Claude/claude_desktop_config.json",
    ),
    Platform.CLINE: (
        ".continue/config.json",
        ".continue/config.yaml",
    ),
    Platform.COPILOT: (
        ".copilot/mcp-config.json",
    ),
    Platform.GEMINI: (
        ".gemini/settings.json",
        ".gemini/GEMINI.md",
        ".gemini/commands",
        ".gemini/extensions",
    ),
    # Zed, opencode, and Goose use ~/.config on macOS as well as Linux.
    Platform.ZED: (
        ".config/zed/settings.json",
        ".config/zed/tasks.json",
    ),
    Platform.OPENCODE: (
        ".config/opencode/opencode.json",
        ".config/opencode/opencode.jsonc",
        ".config/opencode/AGENTS.md",
        ".config/opencode/agents",
        ".config/opencode/agent",
        ".config/opencode/commands",
        ".config/opencode/command",
    ),
    Platform.ROO: (
        "Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        "Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/custom_modes.yaml",
        ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",
        ".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/custom_modes.yaml",
        ".roo/rules",
    ),
    Platform.KIRO: (
        ".kiro/settings/mcp.json",
        ".kiro/steering",
        ".kiro/agents",
    ),
    Platform.AMAZONQ: (
        ".aws/amazonq/mcp.json",
        ".aws/amazonq/default.json",
        ".aws/amazonq/cli-agents",
    ),
    Platform.AIDER: (".aider.conf.yml",),
    Platform.GOOSE: (
        ".config/goose/config.yaml",
        ".config/goose/.goosehints",
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
            return sorted([*root.glob("*/package.json"), *root.glob("*/gemini-extension.json")])
        return sorted(path for path in root.rglob("*") if path.is_file())
    return []


def audit_local_ide_configs(
    home: Path | None = None,
    allowed_publishers: set[str] | None = None,
    governed: bool = False,
) -> ScanResult:
    """Audit user-level IDE configuration files on the local machine.

    The audit intentionally stays static and file-scoped. It reads known
    VS Code-compatible user config locations, runs the normal scanner checks,
    and returns findings without collecting unrelated workstation state.

    When *allowed_publishers* is provided, installed extension manifests are
    additionally checked against that trusted-publisher allowlist.
    """
    from .checks.extensions import check_unknown_publisher

    target = (home or Path.home()).resolve()
    allowed_publishers = allowed_publishers or set()
    findings: list[Finding] = []
    exceptions: list[AcceptedException] = []
    files_scanned = 0
    platforms_detected: list[Platform] = []

    for platform, rel_paths in LOCAL_IDE_FILES.items():
        platform_seen = False
        for rel_path in rel_paths:
            for path in _iter_existing_files(target / rel_path):
                files_scanned += 1
                platform_seen = True
                inline: list[AcceptedException] = []
                for finding in scan_file(path, governed=governed, exceptions=inline):
                    finding.platform = platform
                    findings.append(finding)
                exceptions.extend(
                    replace(exc, path=path.relative_to(target).as_posix()) for exc in inline
                )
                if allowed_publishers:
                    try:
                        content = path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        content = ""
                    for finding in check_unknown_publisher(path, content, allowed_publishers):
                        finding.platform = platform
                        findings.append(finding)
        if platform_seen:
            platforms_detected.append(platform)

    return ScanResult(
        target=target,
        findings=findings,
        files_scanned=files_scanned,
        platforms_detected=platforms_detected or [Platform.GENERIC],
        exceptions=exceptions,
    )
