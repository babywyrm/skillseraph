"""MCP servers launched from a package registry without an exact version."""

import json
from pathlib import Path

import pytest

from skillseraph.scanner import scan_file

CHECK = "mcp_server_unpinned_package"


def _evidence(tmp_path: Path, command: str, args: list[str]) -> list[str]:
    config = tmp_path / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"mcpServers": {"s": {"command": command, "args": args}}}))
    return [f.evidence for f in scan_file(config) if f.check == CHECK]


@pytest.mark.parametrize(
    ("command", "args", "spec"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"], "@modelcontextprotocol/server-filesystem"),
        ("npx", ["mcp-demo@latest"], "mcp-demo@latest"),
        ("npx", ["mcp-demo@^1.2.0"], "mcp-demo@^1.2.0"),
        ("bunx", ["mcp-demo"], "mcp-demo"),
        ("npm", ["exec", "--yes", "--package", "mcp-demo@1", "--", "mcp-demo"], "mcp-demo@1"),
        ("pnpm", ["dlx", "mcp-demo"], "mcp-demo"),
        ("uvx", ["mcp-server-fetch"], "mcp-server-fetch"),
        ("uvx", ["--from", "mcp-server-fetch>=1.0", "mcp-server-fetch"], "mcp-server-fetch>=1.0"),
        ("/usr/local/bin/uvx", ["mcp-server-fetch@latest"], "mcp-server-fetch@latest"),
    ],
)
def test_unpinned_launches(tmp_path: Path, command: str, args: list[str], spec: str):
    assert _evidence(tmp_path, command, args) == [f"{Path(command).name} {spec}"]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"]),
        ("npx", ["mcp-demo@1.4.0-beta.2"]),
        ("npx", ["--package=mcp-demo@1.4.0", "mcp-demo"]),
        ("uvx", ["mcp-server-fetch==2025.4.7"]),
        ("uvx", ["mcp-server-fetch@0.6.2"]),
        ("uvx", ["--from", "mcp-server-fetch==0.6.2", "mcp-server-fetch"]),
        ("npx", ["./local-server"]),
        ("uvx", ["--from", "git+https://example.com/x.git@0123456789abcdef0123456789abcdef01234567", "x"]),
        ("node", ["server.js"]),
        ("npm", ["run", "start"]),
    ],
)
def test_pinned_local_or_non_registry_is_quiet(tmp_path: Path, command: str, args: list[str]):
    assert _evidence(tmp_path, command, args) == []


REMOTE = "mcp_server_npx_remote_package"


def _checks(tmp_path: Path, body: str) -> set[str]:
    config = tmp_path / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(body)
    return {f.check for f in scan_file(config)}


@pytest.mark.parametrize("one_line", [True, False])
def test_scoped_registry_package_is_unpinned_not_critical(tmp_path: Path, one_line: bool):
    data = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}
    checks = _checks(tmp_path, json.dumps(data) if one_line else json.dumps(data, indent=2))
    assert CHECK in checks
    assert REMOTE not in checks


@pytest.mark.parametrize(
    "spec", ["github:evil/pkg", "gitlab:evil/pkg", "git+https://evil.example/pkg.git", "https://evil.example/pkg.tgz"]
)
@pytest.mark.parametrize("one_line", [True, False])
def test_git_or_url_source_is_critical_not_unpinned(tmp_path: Path, spec: str, one_line: bool):
    data = {"mcpServers": {"x": {"command": "npx", "args": ["-y", spec]}}}
    checks = _checks(tmp_path, json.dumps(data) if one_line else json.dumps(data, indent=2))
    assert REMOTE in checks
    assert CHECK not in checks


def test_vscode_servers_key(tmp_path: Path):
    config = tmp_path / ".vscode" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"servers": {"s": {"type": "stdio", "command": "uvx", "args": ["mcp-x"]}}}))
    assert [f.evidence for f in scan_file(config) if f.check == CHECK] == ["uvx mcp-x"]


def test_codex_toml_and_string_command(tmp_path: Path):
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers.a]\ncommand = "npx -y mcp-demo"\n')
    assert [f.evidence for f in scan_file(config) if f.check == CHECK] == ["npx mcp-demo"]
