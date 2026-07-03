"""MCP server definition scanning.

Combines the line-regex rules in rules/mcp_servers.yaml with a structural
JSON pass that catches multi-line field tampering the regex engine cannot
see (an ``env`` block or tool allowlist formatted one key per line).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding, Severity
from ..rules_engine import run_category

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
}

_CREDENTIAL_KEY = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)
_TOOL_LIST_KEYS = ("allowedTools", "tools", "enabledTools")


def _is_mcp_config(path: Path) -> bool:
    return (
        path.name in MCP_CONFIG_NAMES
        or path.match(".cursor/mcp.json")
        or path.match("**/.cursor/mcp.json")
        or path.match(".windsurf/mcp.json")
        or path.match("**/.windsurf/mcp.json")
    )


def check_mcp_servers(path: Path, content: str) -> list[Finding]:
    if not _is_mcp_config(path):
        return []
    findings = run_category("mcp_servers", path, content)
    seen_checks = {f.check for f in findings}
    findings.extend(_structural_checks(path, content, seen_checks))
    return findings


def _structural_checks(path: Path, content: str, seen: set[str]) -> list[Finding]:
    """JSON-aware pass for fields the line-based regex rules miss."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            env = node.get("env")
            if (
                "mcp_server_env_credential_injection" not in seen
                and isinstance(env, dict)
                and any(_CREDENTIAL_KEY.search(k) for k in env)
            ):
                seen.add("mcp_server_env_credential_injection")
                findings.append(Finding(
                    path=path,
                    check="mcp_server_env_credential_injection",
                    severity=Severity.HIGH,
                    title="MCP server definition injects credential via environment",
                    detail=(
                        "The MCP server entry passes credentials through environment "
                        "variables. If this config is attacker-controlled, the "
                        "credentials are exfiltrated to the server on connect."
                    ),
                    evidence="env keys: " + ", ".join(sorted(env)[:5]),
                    taxonomy_id="MCP-T07",
                    atlas_id="J4",
                ))
            for key in _TOOL_LIST_KEYS:
                value = node.get(key)
                if (
                    "mcp_server_wildcard_tool_allowlist" not in seen
                    and isinstance(value, list)
                    and "*" in value
                ):
                    seen.add("mcp_server_wildcard_tool_allowlist")
                    findings.append(Finding(
                        path=path,
                        check="mcp_server_wildcard_tool_allowlist",
                        severity=Severity.MEDIUM,
                        title="MCP server enables all tools via wildcard",
                        detail=(
                            "A wildcard tool allowlist grants the server access to "
                            "every capability, defeating least-privilege."
                        ),
                        evidence=f'"{key}": ["*"]',
                        taxonomy_id="MCP-T09",
                        atlas_id="J3",
                    ))
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return findings
