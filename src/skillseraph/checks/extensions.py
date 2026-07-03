"""Installed IDE extension manifest checks (structural JSON parsing)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding, Platform, Severity

EXTENSION_DIR_MARKERS = (".vscode/extensions", ".cursor/extensions", ".windsurf/extensions")

_REMOTE_EXEC = re.compile(
    r"(curl|wget)\s+\S*https?://\S*(\||;|&&)|https?://\S+\.(sh|py|js)\b",
    re.IGNORECASE,
)
_LIFECYCLE_KEYS = ("preinstall", "postinstall", "install", "prepare", "prepublish")


def _is_extension_manifest(path: Path) -> bool:
    if path.name != "package.json":
        return False
    posix = path.as_posix()
    return any(marker in posix for marker in EXTENSION_DIR_MARKERS)


def check_extension_manifest(path: Path, content: str) -> list[Finding]:
    """Audit an installed extension's package.json for compromise indicators."""
    if not _is_extension_manifest(path):
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []

    activation = data.get("activationEvents")
    if isinstance(activation, list) and "*" in activation:
        findings.append(Finding(
            path=path,
            check="ext_wildcard_activation",
            severity=Severity.MEDIUM,
            title="Extension activates on every IDE event",
            detail=(
                "activationEvents contains '*', so the extension runs on startup with "
                "full workspace access. Legitimate for some tools, but a common trait "
                "of malicious or trojanized extensions."
            ),
            evidence='"activationEvents": ["*"]',
            platform=Platform.VSCODE,
            taxonomy_id="MCP-T08",
            atlas_id="D3",
        ))

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key in _LIFECYCLE_KEYS:
            value = scripts.get(key)
            if isinstance(value, str) and _REMOTE_EXEC.search(value):
                findings.append(Finding(
                    path=path,
                    check="ext_lifecycle_remote_exec",
                    severity=Severity.CRITICAL,
                    title="Extension lifecycle script fetches and runs remote code",
                    detail=(
                        f"The '{key}' script downloads or executes remote content during "
                        "install/update. This runs before the extension is ever opened "
                        "and is a classic extension supply-chain execution vector."
                    ),
                    evidence=f'"{key}": "{value[:150]}"',
                    platform=Platform.VSCODE,
                    taxonomy_id="MCP-T08",
                    atlas_id="D3",
                ))

    main = data.get("main")
    if isinstance(main, str) and (main.startswith("..") or main.startswith("/")):
        findings.append(Finding(
            path=path,
            check="ext_main_path_escape",
            severity=Severity.HIGH,
            title="Extension entry point escapes its install directory",
            detail=(
                "The 'main' field points outside the extension's own directory, so the "
                "IDE loads code from an attacker-controllable location instead of the "
                "packaged extension."
            ),
            evidence=f'"main": "{main[:150]}"',
            platform=Platform.VSCODE,
            taxonomy_id="MCP-T09",
            atlas_id="D3",
        ))

    return findings
