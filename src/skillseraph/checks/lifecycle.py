"""Structural lifecycle/hook command checks (devcontainer.json, hooks.json).

Lifecycle commands are frequently written as arrays (``["bash", "-c", "..."]``)
or per-key objects, so a dangerous ``curl … | sh`` can be split across lines
where the line-regex engine never sees the whole pipeline. This pass parses
the JSON and reassembles each command before matching.

Agent clients also run commands from their own settings: Claude Code,
Gemini CLI, and Amazon Q agent ``hooks``, Claude ``statusLine``, Codex inline
``[hooks]`` and ``notify``, and Aider ``test-cmd``/``lint-cmd``/
``notifications-command``. Only those parts are read, so MCP server commands
in the same file stay with the MCP checks.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..models import Finding, Severity
from . import is_amazonq_agent, load_jsonc

_LIFECYCLE_FILES = ("devcontainer.json", "hooks.json")
_LIFECYCLE_KEYS = (
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
    "initializeCommand",
    "command",
    "notify",
)
_SETTINGS_KEYS = ("hooks", "statusLine", "notify")
_AIDER_COMMAND_KEYS = ("test-cmd", "lint-cmd", "notifications-command")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_REMOTE_EXEC = re.compile(
    r"(curl|wget)\b[^\n]*?https?://[^\n]*?(\|\s*|-O-\s*\|\s*|;\s*|&&\s*)?(bash|sh|zsh|python|node)\b"
    r"|https?://\S+\.(sh|py|js)\b\s*\|\s*(bash|sh|zsh|python|node)",
    re.IGNORECASE,
)


def _command_tree(path: Path, content: str) -> object | None:
    """The parsed parts of a file whose commands run automatically."""
    name, parent = path.name, path.parent.name
    if name in _LIFECYCLE_FILES:
        return load_jsonc(content)
    data: object
    if name == "config.toml" and parent == ".codex":
        try:
            data = tomllib.loads(content)
        except tomllib.TOMLDecodeError:
            return None
    elif name == ".aider.conf.yml":
        try:
            aider = yaml.safe_load(content)
        except yaml.YAMLError:
            return None
        if not isinstance(aider, dict):
            return None
        return [{"command": aider[k]} for k in _AIDER_COMMAND_KEYS if k in aider]
    elif (name in {"settings.json", "settings.local.json"} and ".claude" in path.parts) or (
        name == "settings.json" and parent == ".gemini"
    ) or is_amazonq_agent(path):
        data = load_jsonc(content)
    else:
        return None
    return {k: data[k] for k in _SETTINGS_KEYS if k in data} if isinstance(data, dict) else None


def _remote_http_hosts(node: object) -> list[str]:
    if isinstance(node, list):
        return [h for item in node for h in _remote_http_hosts(item)]
    if not isinstance(node, dict):
        return []
    hosts = [h for value in node.values() for h in _remote_http_hosts(value)]
    url = node.get("url")
    if node.get("type") == "http" and isinstance(url, str):
        host = urlparse(url).hostname
        if host and host not in _LOCAL_HOSTS:
            hosts.append(host)
    return hosts


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
        return [part for sub in value.values() for part in _flatten(sub)]
    return []


def check_lifecycle(path: Path, content: str) -> list[Finding]:
    """Detect remote-fetch-to-interpreter commands in lifecycle/hook configs."""
    data = _command_tree(path, content)
    if data is None:
        return []

    findings: list[Finding] = []
    hosts = sorted(set(_remote_http_hosts(data)))
    if hosts:
        findings.append(Finding(
            path=path,
            check="agent_hook_remote_http",
            severity=Severity.HIGH,
            title="Agent hook posts tool events to an external host",
            detail=(
                "An HTTP hook sends each matching event, including tool inputs such as "
                "commands and file contents, to a host outside this machine."
            ),
            evidence=f"http hook -> {', '.join(hosts[:5])}",
            taxonomy_id="MCP-T12",
            atlas_id="J3",
        ))
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
