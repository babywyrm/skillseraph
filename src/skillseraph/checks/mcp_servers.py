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
import shlex
import tomllib
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ..models import Finding, Severity
from ..rules_engine import run_category
from . import TOKEN_SHAPES, is_amazonq_agent, load_jsonc

MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "claude_desktop_config.json",
    "mcp_settings.json",
}

_CREDENTIAL_KEY = re.compile(r"(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|AUTH)", re.IGNORECASE)
_TOOL_LIST_KEYS = ("allowedTools", "tools", "enabledTools", "enabled_tools", "includeTools", "autoApprove")
_AUTH_PREFIX = re.compile(r"(?i)^(?:bearer|basic|token)\s+")
_VALUE_REFERENCE = re.compile(r"\$\{?[\w:.-]+\}?|\{env:[\w.-]+\}")
_PLACEHOLDER = re.compile(r"(?i)^(?:<[^>]*>|your[_-].*|.*placeholder.*|changeme|x+|\*+|redacted|example.*)$")
_TLS_KEYS = ("tls", "ssl", "verify", "verify_ssl", "tls_verify")
URL_FIELDS = ("url", "httpUrl", "endpoint", "baseUrl", "uri")
_SHELL_COMMAND = re.compile(
    r"(curl|wget|\b(?:bash|sh|zsh)\s+-c\b|\b(?:bash|sh|zsh)\b.*\||\beval\b)",
    re.IGNORECASE,
)
_SHELLS = {"sh", "bash", "zsh", "dash"}
_REMOTE_LAUNCH = re.compile(r"(npx|uvx|pip install|npm exec)", re.IGNORECASE)
_REMOTE_REF = re.compile(r"(git\+|https?://|\b(?:github|gitlab|bitbucket|gist):)", re.IGNORECASE)
_RUNNERS = {"npx", "bunx", "pnpx", "uvx"}
_SUBCOMMAND_RUNNERS = {"npm": "exec", "pnpm": "dlx", "yarn": "dlx", "bun": "x"}
_NPM_VALUE_FLAGS = {"--registry", "--cache", "-c", "--call", "--userconfig"}
_UV_VALUE_FLAGS = {"--python", "-p", "--with", "--index", "--index-url", "--extra-index-url", "--default-index"}
_EXACT_NPM = re.compile(r"\d+\.\d+\.\d+(?:[-+][\w.+-]+)?")
_EXACT_PY = re.compile(r"[\w.\-]+(?:\[[\w,\-]+\])?(?:==|@)\d[\w.+!-]*")
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
    if is_amazonq_agent(path):
        return "mcpServers"
    return None


def _goose_servers(content: str) -> list[tuple[str, dict[str, object]]]:
    """Goose ``extensions`` are MCP servers with cmd/uri/envs field names."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return []
    extensions = data.get("extensions") if isinstance(data, dict) else None
    if not isinstance(extensions, dict):
        return []
    return [
        (str(name), {**ext, "command": ext.get("cmd"), "url": ext.get("uri"), "env": ext.get("envs")})
        for name, ext in extensions.items()
        if isinstance(ext, dict) and ext.get("type") not in {"builtin", "platform"}
    ]


def server_entries(path: Path, content: str) -> list[tuple[str, dict[str, object]]]:
    """(name, definition) for each MCP server the file declares, in any supported format."""
    if path.name == "config.yaml" and path.parent.name == "goose":
        return _goose_servers(content)
    key = _embedded_servers_key(path)
    tables: list[object] = []
    if key:
        data = load_jsonc(content)
        servers = data.get(key) if isinstance(data, dict) else None
        if isinstance(servers, dict) and isinstance(servers.get("servers"), dict):
            servers = servers["servers"]  # opencode v2 nests names under mcp.servers
        tables.append(servers)
    elif _is_codex_config(path):
        try:
            tables.append(tomllib.loads(content).get("mcp_servers"))
        except tomllib.TOMLDecodeError:
            return []
    elif _is_mcp_config(path):
        data = load_jsonc(content)
        if isinstance(data, dict):
            tables.extend(data.get(k) for k in ("mcpServers", "servers"))
    return [
        (str(name), server)
        for table in tables
        if isinstance(table, dict)
        for name, server in table.items()
        if isinstance(server, dict)
    ]


def check_mcp_servers(path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    if _is_mcp_config(path):
        findings = run_category("mcp_servers", path, content)
        seen = {f.check for f in findings}
        if not _is_codex_config(path):
            findings.extend(_structural_checks(path, content, seen))
    for _, server in server_entries(path, content):
        _inspect_server(path, server, findings, seen)
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


def command_line(server: dict[str, object]) -> str:
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


def _package_spec(launched: str) -> tuple[str, str] | None:
    """(launcher, package spec) when a registry runner starts the server."""
    try:
        argv = shlex.split(launched)
    except ValueError:
        return None
    if not argv:
        return None
    launcher, rest = Path(argv[0]).name, argv[1:]
    if launcher in _SUBCOMMAND_RUNNERS:
        if not rest or rest[0] != _SUBCOMMAND_RUNNERS[launcher]:
            return None
        rest = rest[1:]
    elif launcher not in _RUNNERS:
        return None
    python = launcher == "uvx"
    package_flags = {"--from"} if python else {"-p", "--package"}
    # ponytail: known value-taking flags only; an unknown one shifts the spec to its value.
    value_flags = _UV_VALUE_FLAGS if python else _NPM_VALUE_FLAGS
    i = 0
    while i < len(rest):
        flag, eq, value = rest[i].partition("=")
        if flag in package_flags:
            spec = value if eq else (rest[i + 1] if i + 1 < len(rest) else "")
            return (launcher, spec) if spec else None
        if flag in value_flags and not eq:
            i += 2
        elif rest[i].startswith("-"):
            i += 1
        else:
            return launcher, rest[i]
    return None


def _unpinned(launcher: str, spec: str) -> bool:
    if spec.startswith((".", "/", "~", "file:")) or _REMOTE_REF.search(spec):
        return False
    if launcher == "uvx":
        return not _EXACT_PY.fullmatch(spec)
    version = spec.lstrip("@").partition("@")[2]
    return not _EXACT_NPM.fullmatch(version)


def _inspect_server(
    path: Path,
    server: dict[str, object],
    findings: list[Finding],
    seen: set[str],
) -> None:
    launched = command_line(server)
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
            "MCP server runs a package straight from git or a URL",
            "The server definition runs code fetched from a git host or URL at agent startup.",
            launched,
            "MCP-T08",
            "J6",
        )

    package = _package_spec(launched)
    if package and _unpinned(*package):
        _emit(
            findings, seen, path,
            "mcp_server_unpinned_package",
            Severity.MEDIUM,
            "MCP server package is not pinned to an exact version",
            "Each agent start resolves the newest matching release, so a compromised "
            "or hijacked publish runs without any config change.",
            " ".join(package),
            "MCP-T08",
            "J6",
        )

    for key in URL_FIELDS:
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

    literal = [
        f"{field}: {', '.join(names[:5])}"
        for field, names in (("env", _literal_secret_keys(env)), ("headers", _literal_secret_keys(server.get("headers"))))
        if names
    ]
    if literal:
        _emit(
            findings, seen, path,
            "mcp_server_literal_secret",
            Severity.HIGH,
            "MCP server config holds a literal secret",
            "A credential is written into the config instead of referenced from the "
            "environment, so anyone who can read or copy this file has it.",
            "; ".join(literal),
            "MCP-T07",
            "J4",
        )


def _literal_secret_keys(block: object) -> list[str]:
    """Credential-named or token-shaped keys whose value is not a reference or placeholder."""
    if not isinstance(block, dict):
        return []
    names = []
    for key, value in block.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        bare = _AUTH_PREFIX.sub("", value.strip())
        if len(bare) < 6 or _VALUE_REFERENCE.search(bare) or _PLACEHOLDER.match(bare):
            continue
        if _CREDENTIAL_KEY.search(key) or TOKEN_SHAPES.search(bare):
            names.append(key)
    return sorted(names)


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
