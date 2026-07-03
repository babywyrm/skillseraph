"""MCP server definition scanning (rules in rules/mcp_servers.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
}


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
    return run_category("mcp_servers", path, content)
