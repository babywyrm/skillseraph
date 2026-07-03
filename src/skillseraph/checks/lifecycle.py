"""Structural lifecycle/hook command checks (devcontainer.json, hooks.json).

Lifecycle commands are frequently written as arrays (``["bash", "-c", "..."]``)
or per-key objects, so a dangerous ``curl … | sh`` can be split across lines
where the line-regex engine never sees the whole pipeline. This pass parses
the JSON and reassembles each command before matching.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding, Severity

_LIFECYCLE_FILES = ("devcontainer.json", "hooks.json")
_LIFECYCLE_KEYS = (
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
    "initializeCommand",
    "command",
)
_REMOTE_EXEC = re.compile(
    r"(curl|wget)\b[^\n]*?https?://[^\n]*?(\|\s*|-O-\s*\|\s*|;\s*|&&\s*)?(bash|sh|zsh|python|node)\b"
    r"|https?://\S+\.(sh|py|js)\b\s*\|\s*(bash|sh|zsh|python|node)",
    re.IGNORECASE,
)


def _is_lifecycle_file(path: Path) -> bool:
    return path.name in _LIFECYCLE_FILES


def _collect_command_strings(node: object) -> list[str]:
    """Reassemble candidate command strings from lifecycle/hook fields."""
    commands: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _LIFECYCLE_KEYS:
                commands.extend(_flatten(value))
            commands.extend(_collect_command_strings(value))
    elif isinstance(node, list):
        for item in node:
            commands.extend(_collect_command_strings(item))
    return commands


def _flatten(value: object) -> list[str]:
    """Turn a lifecycle command value (str | list | dict) into joined strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        joined = " ".join(v for v in value if isinstance(v, str))
        parts = [joined] if joined else []
        for item in value:
            if isinstance(item, (list, dict)):
                parts.extend(_flatten(item))
        return parts
    if isinstance(value, dict):
        parts: list[str] = []
        for sub in value.values():
            parts.extend(_flatten(sub))
        return parts
    return []


def check_lifecycle(path: Path, content: str) -> list[Finding]:
    """Detect remote-fetch-to-interpreter commands in lifecycle/hook configs."""
    if not _is_lifecycle_file(path):
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for command in _collect_command_strings(data):
        if _REMOTE_EXEC.search(command):
            findings.append(Finding(
                path=path,
                check="lifecycle_remote_exec",
                severity=Severity.CRITICAL,
                title="Lifecycle/hook command fetches and runs remote code",
                detail=(
                    "A lifecycle or hook command downloads remote content and pipes it "
                    "into an interpreter. This runs automatically on container "
                    "create/start or agent hook events, before any review."
                ),
                evidence=command[:200],
                taxonomy_id="MCP-T08",
                atlas_id="J3",
            ))
    return findings
