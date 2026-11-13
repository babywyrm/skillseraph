"""MCP server definition scanning.

Combines the line-regex rules in rules/mcp_servers.yaml with a structural
pass for fields the line engine cannot see. JSON covers multi-line ``env``
blocks. Codex ``.codex/config.toml`` stores the same servers as TOML tables,
so those files get a ``tomllib`` pass. Clients that embed servers in their
own settings (Claude Code, Gemini CLI, Zed, opencode, Copilot CLI) get a
pass over just that key. Evidence lists key names, never values.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from urllib.parse import urlparse

from ..models import Finding, Severity
from ..rules_engine import run_category
from . import load_jsonc

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
}

_CREDENTIAL_KEY = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)
_TOOL_LIST_KEYS = ("allowedTools", "tools", "enabledTools", "enabled_tools", "includeTools")
_TLS_KEYS = ("tls", "ssl", "verify", "verify_ssl", "tls_verify")
_URL_FIELDS = ("url", "httpUrl", "endpoint", "baseUrl", "uri")
_SHELL_COMMAND = re.compile(
    r"(curl|wget|\b(?:bash|sh|zsh)\s+-c\b|\b(?:bash|sh|zsh)\b.*\||\beval\b)",
    re.IGNORECASE,
)
_SHELLS = {"sh", "bash", "zsh", "dash"}
_REMOTE_LAUNCH = re.compile(r"(npx|uvx|pip install|npm exec)", re.IGNORECASE)
_REMOTE_REF = re.compile(r"(@|git\+|https?://)", re.IGNORECASE)
_LOCAL_URL = re.compile(
    r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::|/|$)",
    re.IGNORECASE,
)


def _is_codex_config(path: Path) -> bool:
    return path.name == "config.toml" and path.parent.name == ".codex"


def _is_mcp_config(path: Path) -> bool:
    return (
        path.name in MCP_CONFIG_NAMES
        or path.match(".cursor/mcp.json")
        or path.match("**/.cursor/mcp.json")
        or path.match(".windsurf/mcp.json")
        or path.match("**/.windsurf/mcp.json")
        or _is_codex_config(path)
    )


def _embedded_servers_key(path: Path) -> str | None:
    """Top-level key holding MCP servers in a client's own settings file."""
    name, parent = path.name, path.parent.name
    if name in {"settings.json", "settings.local.json"} and ".claude" in path.parts:
        return "mcpServers"
    if (name == "settings.json" and parent == ".gemini") or name == "gemini-extension.json":
        return "mcpServers"
    if name == "mcp-config.json" and parent == ".copilot":
        return "mcpServers"
    if name == "settings.json" and parent in {".zed", "zed"}:
        return "context_servers"
    if name in {"opencode.json", "opencode.jsonc"}:
        return "mcp"
    return None


def check_mcp_servers(path: Path, content: str) -> list[Finding]:
    key = _embedded_servers_key(path)
    if key:
        return _embedded_server_checks(path, content, key)
    if not _is_mcp_config(path):
        return []
    findings = run_category("mcp_servers", path, content)
    seen_checks = {f.check for f in findings}
    if _is_codex_config(path):
        findings.extend(_toml_checks(path, content, seen_checks))
    else:
        findings.extend(_structural_checks(path, content, seen_checks))
    return findings


def _emit(
    findings: list[Finding],
    seen: set[str],
    path: Path,
    check: str,
    severity: Severity,
    title: str,
    detail: str,
    evidence: str,
    taxonomy_id: str,
    atlas_id: str,
) -> None:
    if check in seen:
        return
    seen.add(check)
    findings.append(Finding(
        path=path,
        check=check,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence[:200],
        taxonomy_id=taxonomy_id,
        atlas_id=atlas_id,
    ))


def _command_line(server: dict[str, object]) -> str:
    parts: list[str] = []
    command = server.get("command")
    if isinstance(command, str):
        parts.append(command)
    elif isinstance(command, list):
        parts.extend(item for item in command if isinstance(item, str))
    args = server.get("args")
    if isinstance(args, str):
        parts.append(args)
    elif isinstance(args, list):
        parts.extend(item for item in args if isinstance(item, str))
    return " ".join(parts)


def _inspect_server(
    path: Path,
    server: dict[str, object],
    findings: list[Finding],
    seen: set[str],
) -> None:
    launched = _command_line(server)
    argv0 = launched.split(" ", 1)[0]
    shell_target = launched if Path(argv0).name in _SHELLS else argv0
    if _SHELL_COMMAND.search(shell_target):
        _emit(
            findings, seen, path,
            "mcp_server_stdio_arbitrary_command",
            Severity.CRITICAL,
            "MCP server launches a shell/fetch command via stdio",
            "The server definition uses stdio transport with a shell or download command.",
            launched,
            "MCP-T09",
            "J4",
        )

    for key in _TOOL_LIST_KEYS:
        tools = server.get(key)
        if isinstance(tools, list) and "*" in tools:
            _emit(
                findings, seen, path,
                "mcp_server_wildcard_tool_allowlist",
                Severity.MEDIUM,
                "MCP server enables all tools via wildcard",
                "A wildcard tool allowlist grants the server every capability.",
                f'{key} = ["*"]',
                "MCP-T09",
                "J3",
            )
            break

    env = server.get("env", server.get("environment"))
    tls_off = [k for k in _TLS_KEYS if server.get(k) in (False, 0, "false", "0")]
    if isinstance(env, dict) and str(env.get("NODE_TLS_REJECT_UNAUTHORIZED")) == "0":
        tls_off.append("NODE_TLS_REJECT_UNAUTHORIZED")
    if tls_off:
        _emit(
            findings, seen, path,
            "mcp_server_disabled_tls_verify",
            Severity.HIGH,
            "MCP server definition disables TLS verification",
            "TLS verification is off, so traffic to this server can be intercepted.",
            f"{tls_off[0]} disabled",
            "MCP-T06",
            "J4",
        )

    if server.get("trust") is True:
        _emit(
            findings, seen, path,
            "mcp_server_trust_bypasses_approval",
            Severity.HIGH,
            "MCP server is trusted, so its tool calls skip confirmation",
            "trust: true lets every tool this server exposes run without asking the user.",
            "trust=true",
            "MCP-T03",
            "J2",
        )

    if _REMOTE_LAUNCH.search(launched) and _REMOTE_REF.search(launched):
        _emit(
            findings, seen, path,
            "mcp_server_npx_remote_package",
            Severity.CRITICAL,
            "MCP server fetches and runs a remote package via npx/uvx",
            "The server definition runs a remote package at agent startup.",
            launched,
            "MCP-T08",
            "J6",
        )

    for key in _URL_FIELDS:
        value = server.get(key)
        if not isinstance(value, str) or not value.lower().startswith(("http://", "https://")):
            continue
        if _LOCAL_URL.match(value):
            continue
        host = urlparse(value).hostname or ""
        _emit(
            findings, seen, path,
            "mcp_server_non_local_url",
            Severity.MEDIUM,
            "MCP server points to a non-local endpoint",
            "A registered MCP server connects to a remote URL.",
            f"{key}={host}",
            "MCP-T14",
            "J4",
        )
        break

    if isinstance(env, dict):
        keys = sorted(name for name in env if isinstance(name, str) and _CREDENTIAL_KEY.search(name))
        if keys:
            _emit(
                findings, seen, path,
                "mcp_server_env_credential_injection",
                Severity.HIGH,
                "MCP server definition injects credential via environment",
                "The MCP server entry passes credentials through environment variables.",
                "env keys: " + ", ".join(keys[:5]),
                "MCP-T07",
                "J4",
            )


def _embedded_server_checks(path: Path, content: str, key: str) -> list[Finding]:
    data = load_jsonc(content)
    servers = data.get(key) if isinstance(data, dict) else None
    if isinstance(servers, dict) and isinstance(servers.get("servers"), dict):
        servers = servers["servers"]  # opencode v2 nests names under mcp.servers
    if not isinstance(servers, dict):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for server in servers.values():
        if isinstance(server, dict):
            _inspect_server(path, server, findings, seen)
    return findings


def _toml_checks(path: Path, content: str, seen: set[str]) -> list[Finding]:
    """Codex MCP servers live under ``[mcp_servers.<name>]``, not mcp.json."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []

    servers = data.get("mcp_servers")
    if not isinstance(servers, dict):
        return []

    findings: list[Finding] = []
    for server in servers.values():
        if isinstance(server, dict):
            _inspect_server(path, server, findings, seen)
    return findings


def _structural_checks(path: Path, content: str, seen: set[str]) -> list[Finding]:
    """JSON-aware pass for fields the line-based regex rules miss."""
    data = load_jsonc(content)
    if data is None:
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
